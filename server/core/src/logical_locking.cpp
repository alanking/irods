#include "logical_locking.hpp"
#include "replica_state_table.hpp"
#include "rs_data_object_finalize.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

namespace
{
    using json = nlohmann::json;
    namespace replica = irods::experimental::replica;
} // anonymous namespace

namespace irods::logical_locking
{
    auto lock(
        RsComm& _comm,
        const std::string_view _logical_path,
        const int _replica_number) -> void
    {
        auto& rst = irods::replica_state_table::instance();

        if (!rst.contains(_logical_path)) {
            THROW(KEY_NOT_FOUND, fmt::format(
                "[{}:{}] - replica state table does not contain [{]]",
                __FUNCTION__, __LINE__, _logical_path));
        }

        for (auto& replica_in_json : rst.at(_logical_path)) {
            auto [r, r_lm] = replica::make_replica_proxy(_logical_path, replica_in_json.at("after"));

            if (r.replica_number() == _replica_number) {
                r.replica_status(INTERMEDIATE_REPLICA);
            }
            else {
                r.replica_status(WRITE_LOCKED_REPLICA);
            }

            irods::replica_state_table::instance().update(
                r.logical_path(), r.replica_number(),
                nlohmann::json{{"data_is_dirty", std::to_string(r.replica_status())}});
        }
    } // lock

    auto unlock(
        RsComm& _comm,
        const std::string_view _logical_path,
        const int _replica_number) -> void
    {
        auto& rst = irods::replica_state_table::instance();

        if (!rst.contains(_logical_path)) {
            THROW(KEY_NOT_FOUND, fmt::format(
                "[{}:{}] - replica state table does not contain [{]]",
                __FUNCTION__, __LINE__, _logical_path));
        }

        for (auto& replica_in_json : rst.at(_logical_path)) {
            auto [r, r_lm] = replica::make_replica_proxy(_logical_path, replica_in_json.at("after"));

            if (r.replica_number() != _replica_number) {
                r.replica_status(std::stoi(
                    rst.get_property(r.logical_path(), r.replica_number(), "data_is_dirty")));
            }

            irods::replica_state_table::instance().update(
                r.logical_path(), r.replica_number(),
                nlohmann::json{{"data_is_dirty", std::to_string(r.replica_status())}});
        }
    } // unlock
}// namespace irods::logical_locking
