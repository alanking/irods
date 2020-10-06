#include "objDesc.hpp"
#include "irods_resource_redirect.hpp"
#include "logical_locking.hpp"
#include "rsGlobalExtern.hpp"
#include "replica_state_table.hpp"

#include "rs_data_object_finalize.hpp"

#include "fmt/format.h"
#include "json.hpp"

#include <map>

namespace irods
{
    namespace
    {
        // clang-format off
        using data_object_type      = irods::experimental::data_object::data_object_proxy<DataObjInfo>;
        using json                  = nlohmann::json;
        using replica_state_table   = irods::experimental::replica_state_table;
        // clang-format on

        auto prepare_finalize_input(std::string_view _logical_path) -> json
        {
            auto& rst = replica_state_table::instance();
            auto before_obj = rst.get_data_object_state(_logical_path, replica_state_table::state_type::before);
            if (!before_obj) {
                THROW(SYS_INTERNAL_ERR, fmt::format("[{}] - missing before state for [{}]", __FUNCTION__, _logical_path));
            }

            auto after_obj = rst.get_data_object_state(_logical_path, replica_state_table::state_type::after);
            if (!after_obj) {
                THROW(SYS_INTERNAL_ERR, fmt::format("[{}] - missing after state for [{}]", __FUNCTION__, _logical_path));
            }

            // TODO: in replication, new replicas will be added to before?
            if (before_obj->replica_count() != after_obj->replica_count()) {
                THROW(SYS_INTERNAL_ERR, "before and after replicas should be bijective");
            }

            json input;
            input["data_id"] = std::to_string(before_obj->data_id());

            for (int i = 0; i < before_obj->replica_count(); ++i) {
                input["replicas"].push_back(json
                    {
                        {"before", irods::experimental::replica::to_json(before_obj->replicas().at(i))},
                        {"after", irods::experimental::replica::to_json(after_obj->replicas().at(i))}
                    }
                );
            }

            return input;
        } // prepare_finalize_input

        auto check_read_lock(const data_object_type& _obj, std::string_view _operation) -> void
        {
            const bool read_locked = std::any_of(
                std::cbegin(_obj.replicas()), std::cend(_obj.replicas()),
                [](const auto& _r) { return READ_LOCK == _r.replica_status(); });
            if (read_locked && (WRITE_OPERATION == _operation || CREATE_OPERATION == _operation)) {
                THROW(DATA_OBJECT_LOCKED, fmt::format(
                    "[{}] - data object [{}] is locked with state [{}]",
                    __FUNCTION__, _obj.logical_path(), READ_LOCK));
            }
        } // check_read_lock

        auto get_intermediate_replica(const data_object_type& _obj)
        {
            const auto& intermediate_replica = std::find_if(
                std::cbegin(_obj.replicas()), std::cend(_obj.replicas()),
                [](const auto& _r) { return INTERMEDIATE_REPLICA == _r.replica_status(); });
            if (std::cend(_obj.replicas()) == intermediate_replica) {
                THROW(WRITE_LOCKED_WITH_NO_OPEN_REPLICA, fmt::format(
                    "[{}] - data object [{}] is write locked but no replica is in the intermediate state",
                    __FUNCTION__, _obj.logical_path(), WRITE_LOCK));
            }
            return *intermediate_replica;
        } // get_intermediate_replica

        auto validate_replication_context(std::string_view _ctx, const data_object_type& _obj) -> void
        {
            using json = nlohmann::json;

            const auto repl_ctx = json::parse(_ctx);
            const auto& data_id = repl_ctx.at("data_id");
            const auto& destination_resc_id = repl_ctx.at("destination_resource_id");

            const auto& intermediate_replica = get_intermediate_replica(_obj);

            if (data_id != _obj.data_id() || destination_resc_id != intermediate_replica.resource_id()) {
                THROW(DATA_OBJECT_LOCKED, fmt::format(
                    "[{}] - data object [{}] is locked with state [{}]",
                    __FUNCTION__, _obj.logical_path(), WRITE_LOCK));
            }

            const auto& source_resc_id = repl_ctx.at("source_resource_id");
            const auto& source_replica = std::find_if(
                std::cbegin(_obj.replicas()), std::cend(_obj.replicas()),
                [&source_resc_id](const auto& _r) { return _r.resource_id() == source_resc_id; });
            if (std::cend(_obj.replicas()) == source_replica) {
                THROW(DATA_OBJECT_LOCKED, fmt::format(
                    "[{}] - data object [{}] is locked with state [{}]",
                    __FUNCTION__, _obj.logical_path(), WRITE_LOCK));
            }
        } // validate_replication_context
    } // anonymouse namespace

    auto lock_data_object(RsComm& _comm, data_object_type& _obj, std::string_view _operation) -> void
    {
        const bool data_at_rest = std::all_of(
            std::cbegin(_obj.replicas()), std::cend(_obj.replicas()),
            [](const auto& _r)
            {
                return STALE_REPLICA == _r.replica_status() ||
                       GOOD_REPLICA  == _r.replica_status();
            });
        if (!data_at_rest) {
            check_read_lock(_obj, _operation);

            if (OPEN_OPERATION != _operation) {
                const auto session_props = irods::experimental::key_value_proxy{_comm.session_props};

                if (!session_props.contains(REPLICATION_CONTEXT_KW)) {
                    THROW(DATA_OBJECT_LOCKED, fmt::format(
                        "[{}] - data object [{}] is locked with state [{}]",
                        __FUNCTION__, _obj.logical_path(), WRITE_LOCK));
                }

                // throws if the replication context is invalid
                validate_replication_context(session_props.at(REPLICATION_CONTEXT_KW).value(), _obj);

                // this is a source replica open - the locking has already happened
                // TODO: this seems wrong...
                return;
            }
        }

        auto& rst = replica_state_table::instance();

        if (!rst.contains(_obj.logical_path())) {
            rst.create_entry(_obj);
        }

        auto before = rst.get_data_object_state(_obj.logical_path(), replica_state_table::state_type::before);

        auto [after, lm] = irods::experimental::data_object::duplicate_data_object(*before);

        for (auto& r : after.replicas()) {
            if (irods::OPEN_OPERATION == _operation) {
                irods::log(LOG_NOTICE, fmt::format("[{}] - setting read lock for [{}] of [{}]",
                    __FUNCTION__, r.replica_number(), r.logical_path()));
                r.replica_status(READ_LOCK);
            }
            else if (irods::WRITE_OPERATION == _operation) {
                irods::log(LOG_NOTICE, fmt::format("[{}] - setting write lock for [{}] of [{}]",
                    __FUNCTION__, r.replica_number(), r.logical_path()));
                r.replica_status(WRITE_LOCK);
            }
            else if (irods::CREATE_OPERATION == _operation) {
                irods::log(LOG_NOTICE, fmt::format("[{}] - not locking for create for [{}] of [{}]",
                    __FUNCTION__, r.replica_number(), r.logical_path()));
                r.replica_status(WRITE_LOCK);
            }
            else {
                THROW(INVALID_OPERATION, fmt::format("operation [{}] not supported", _operation));
            }
        }

        rst.set_data_object_state(after.logical_path(), after, replica_state_table::state_type::after);

        const auto input = prepare_finalize_input(_obj.logical_path()).dump();

        irods::log(LOG_NOTICE, fmt::format("[{}:{}] - input to finalize:[{}]", __FUNCTION__, __LINE__, input));

        char* output{};
        if (const int ec = rs_data_object_finalize(&_comm, input.c_str(), &output); ec < 0) {
            THROW(ec, fmt::format("failed to finalize [{}]", _obj.logical_path()));
        }
    } // lock_data_object

    auto unlock_data_object(RsComm& _comm, std::string_view _logical_path) -> void
    {
        auto& rst = replica_state_table::instance();

        auto before = rst.get_data_object_state(_logical_path, replica_state_table::state_type::before);
        if (!before) {
            THROW(SYS_INTERNAL_ERR, fmt::format("[{}] - missing before state for [{}]", __FUNCTION__, _logical_path));
        }

        auto after = rst.get_data_object_state(_logical_path, replica_state_table::state_type::after);
        if (!after) {
            THROW(SYS_INTERNAL_ERR, fmt::format("[{}] - missing after state for [{}]", __FUNCTION__, _logical_path));
        }

        for (int i = 0; i < after->replica_count(); ++i) {
            auto& before_replica = before->replicas().at(i);
            auto& after_replica = after->replicas().at(i);

            irods::log(LOG_NOTICE, fmt::format(
                "[{}:{}] - BEFORE replica:[{}]",
                __FUNCTION__, __LINE__,
                irods::experimental::replica::to_json(before_replica).dump()));

            irods::log(LOG_NOTICE, fmt::format(
                "[{}:{}] - AFTER replica:[{}]",
                __FUNCTION__, __LINE__,
                irods::experimental::replica::to_json(after_replica).dump()));

            switch (after_replica.replica_status()) {
                case READ_LOCK:
                    irods::log(LOG_NOTICE, fmt::format(
                        "[{}:{}] - obj:[{}],repl:[{}],before:[{}],after:[{}]",
                        __FUNCTION__, __LINE__,
                        after_replica.logical_path(),
                        after_replica.replica_number(),
                        before_replica.replica_status(),
                        after_replica.replica_status()));

                    after_replica.replica_status(before_replica.replica_status());

                    // TODO: need to update status field to include refcount

                    irods::log(LOG_NOTICE, fmt::format(
                        "[{}:{}] - obj:[{}],repl:[{}],before:[{}],after:[{}]",
                        __FUNCTION__, __LINE__,
                        after_replica.logical_path(),
                        after_replica.replica_number(),
                        before_replica.replica_status(),
                        after_replica.replica_status()));
                    break;

                // TODO: this should already be modified in close?
                case WRITE_LOCK:
                    [[fallthrough]];
                case INTERMEDIATE_REPLICA:
                    irods::log(LOG_NOTICE, fmt::format(
                        "[{}:{}] - obj:[{}],repl:[{}],before:[{}],after:[{}]",
                        __FUNCTION__, __LINE__,
                        after_replica.logical_path(),
                        after_replica.replica_number(),
                        before_replica.replica_status(),
                        after_replica.replica_status()));
                    break;

                case GOOD_REPLICA:
                    [[fallthrough]];
                case STALE_REPLICA:
                    [[fallthrough]];
                default:
                    // do nothing
                    irods::log(LOG_NOTICE, fmt::format(
                        "[{}:{}] - obj:[{}],repl:[{}],before:[{}],after:[{}]",
                        __FUNCTION__, __LINE__,
                        after_replica.logical_path(),
                        after_replica.replica_number(),
                        before_replica.replica_status(),
                        after_replica.replica_status()));
                    break;
            }
        }

        rst.set_data_object_state(after->logical_path(), *after, replica_state_table::state_type::after);

        const auto input = prepare_finalize_input(_logical_path).dump();

        char* output{};
        if (const int ec = rs_data_object_finalize(&_comm, input.c_str(), &output); ec < 0) {
            THROW(ec, fmt::format("failed to finalize [{}]", _logical_path));
        }

        rst.erase_entry(_logical_path);
    } // unlock_data_object
} // namespace irods

