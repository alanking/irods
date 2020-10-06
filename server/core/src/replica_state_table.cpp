#include "replica_state_table.hpp"

#include "fmt/format.h"

#include <map>

namespace irods::experimental
{
    namespace
    {
        // clang-format off
        using data_object_proxy  = replica_state_table::data_object_proxy;
        using maybe_data_object = replica_state_table::maybe_data_object;
        using state_type        = replica_state_table::state_type;
        using key_type          = replica_state_table::key_type;
        using value_type        = replica_state_table::entry;
        using data_object_handle = replica_state_table::data_object_handle;
        // clang-format on

        // Global Variables
        std::map<key_type, value_type> g_state_map;

        auto duplicate_and_acquire_data_object(const data_object_proxy& _obj) -> data_object_proxy
        {
            auto [dup, lm] = data_object::duplicate_data_object(_obj);
            // intentionally take ownership of memory
            lm.release();
            return dup;
        } // duplicate_and_acquire_data_object

        auto reset_state_map() -> void
        {
            for (auto& r : g_state_map) {
                auto& e = r.second;
                freeAllDataObjInfo(e.before);
                freeAllDataObjInfo(e.after);
            }

            g_state_map.clear();
        } // reset_state_map
    } // anonymouse namespace

    auto replica_state_table::init() -> void
    {
        irods::log(LOG_DEBUG9, fmt::format("[{}:{}] - initializing state table", __FUNCTION__, __LINE__));
        reset_state_map();
    } // init

    auto replica_state_table::deinit() -> void
    {
        irods::log(LOG_DEBUG9, fmt::format("[{}:{}] - de-initializing state table", __FUNCTION__, __LINE__));
        reset_state_map();
    } // deinit

    auto replica_state_table::instance() noexcept -> replica_state_table&
    {
        static replica_state_table instance;
        irods::log(LOG_DEBUG9, fmt::format("[{}:{}] - retrieving instance of replica state table", __FUNCTION__, __LINE__));
        return instance;
    } // instance

    auto replica_state_table::create_entry(const data_object_proxy& _obj) -> void
    {
        const key_type logical_path = _obj.logical_path().data();

        if (std::end(g_state_map) != g_state_map.find(logical_path)) {
            auto& e = g_state_map.at(logical_path);
            auto& rst = instance();
            rst.set_data_object_state(logical_path, _obj, state_type::before);
            rst.set_data_object_state(logical_path, _obj, state_type::after);
            ++e.ref_count;
            return;
        }

        // duplicates structures, releases pointer to memory from lifetime manager, places in map
        auto before = duplicate_and_acquire_data_object(_obj);
        auto after = duplicate_and_acquire_data_object(_obj);

        entry e{.before = before.get(), .after = after.get(), .ref_count = 1};

        if (!e.before || !e.after) {
            THROW(SYS_UNKNOWN_ERROR, fmt::format(
                "[{}:{}] - invalid before/after states at create time",
                __FUNCTION__, __LINE__));
        }

        g_state_map[logical_path] = e;
    } // create_entry

    auto replica_state_table::erase_entry(const key_type& _logical_path) -> void
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::end(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
        }

        auto& e = itr->second;
        if (e.ref_count > 1) {
            irods::log(LOG_NOTICE, fmt::format("[{}:{}] - (CHANGE TO DEBUG) ref_count:[{}]", __FUNCTION__, __LINE__, e.ref_count));
            --e.ref_count;
            return;
        }

        auto before = data_object_proxy{*e.before};
        auto after = data_object_proxy{*e.after};

        freeAllDataObjInfo(e.before);

        freeAllDataObjInfo(e.after);

        g_state_map.erase(_logical_path);

        irods::log(LOG_NOTICE, fmt::format("[{}:{}] - map size:[{}]", __FUNCTION__, __LINE__, g_state_map.size()));
    } // erase_entry

    auto replica_state_table::contains(const key_type& _logical_path) -> bool
    {
        for (auto&& [k, v] : g_state_map) {
            if (_logical_path == k) {
                return true;
            }
        }
        return false;
    } // contains

    auto replica_state_table::reference_count(const key_type& _logical_path) -> std::uint8_t
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::end(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
        }

        return itr->second.ref_count;
    } // reference_count

    auto replica_state_table::get_data_object_state(
        const key_type& _logical_path,
        const state_type _state) -> maybe_data_object
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            irods::log(LOG_NOTICE, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
            return std::nullopt;
        }

        auto& e = itr->second;

        switch(_state) {
            case state_type::before:
                return data_object::duplicate_data_object(*e.before);

            case state_type::after:
                return data_object::duplicate_data_object(*e.after);

            default:
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                    "invalid state type for getting replica info for [{}]", _logical_path));
                break;
        }
    } // get_data_object_state

    auto replica_state_table::set_data_object_state(
        const key_type& _logical_path,
        const data_object_proxy& _obj,
        const state_type _state) -> void
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
        }

        auto& e = itr->second;
        switch(_state) {
            case state_type::before:
                freeAllDataObjInfo(e.before);
                e.before = duplicate_and_acquire_data_object(_obj).get();
                break;

            case state_type::after:
                freeAllDataObjInfo(e.after);
                e.after = duplicate_and_acquire_data_object(_obj).get();
                break;

            default:
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                    "invalid state type for getting replica info for [{}]", _logical_path));
                break;
        }
    } // set_data_object_state

    auto replica_state_table::to_json(const data_object_proxy& _before, const data_object_proxy& _after) -> nlohmann::json
    {
        using json = nlohmann::json;

        if (_before.replica_count() != _after.replica_count()) {
            THROW(SYS_INTERNAL_ERR, "before and after replicas should be bijective");
        }

        json input;
        input["data_id"] = std::to_string(_before.data_id());

        for (int i = 0; i < _before.replica_count(); ++i) {
            const auto& before_replica = _before.replicas().at(i);
            const auto& after_replica = _after.replicas().at(i);

            input["replicas"].push_back(json
                {
                    {"before", replica::to_json(before_replica)},
                    {"after", replica::to_json(after_replica)}
                }
            );

            try {
                if (after_replica.cond_input().contains(FILE_MODIFIED_KW) &&
                    !after_replica.cond_input().at(FILE_MODIFIED_KW).value().empty()) {
                    auto& entry = input["replicas"].back();
                    entry[FILE_MODIFIED_KW] = json::parse(after_replica.cond_input().at(FILE_MODIFIED_KW).value());
                }
            }
            catch (const json::parse_error& e) {
                irods::log(LOG_ERROR, fmt::format("[{}] - json::parse failed:[{}]", __FUNCTION__, e.what()));
                input["replicas"].back().erase(FILE_MODIFIED_KW);
            }
        }

        irods::log(LOG_DEBUG, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, input.dump()));

        return input;
    } // to_json

    auto replica_state_table::to_json(const key_type& _logical_path) -> nlohmann::json
    {
        auto& rst = replica_state_table::instance();

        auto before = rst.get_data_object_state(_logical_path, state_type::before);
        if (!before) {
            THROW(SYS_INTERNAL_ERR, fmt::format("[{}] - missing before state for [{}]", __FUNCTION__, _logical_path));
        }

        auto after = rst.get_data_object_state(_logical_path, state_type::after);
        if (!after) {
            THROW(SYS_INTERNAL_ERR, fmt::format("[{}] - missing after state for [{}]", __FUNCTION__, _logical_path));
        }

        auto& [before_obj, before_lm] = *before;
        auto& [after_obj, after_lm] = *after;

        return replica_state_table::to_json(before_obj, after_obj);;
    } // to_json
} // namespace irods::experimental

