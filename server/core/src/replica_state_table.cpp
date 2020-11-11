#include "replica_state_table.hpp"

#include "fmt/format.h"

#include <map>

namespace irods::experimental
{
    namespace
    {
        // clang-format off
        using data_object_proxy  = replica_state_table::data_object_proxy;
        using state_type        = replica_state_table::state_type;
        using key_type          = replica_state_table::key_type;
        using value_type        = replica_state_table::entry;
        // clang-format on

        // Global Variables
        std::map<key_type, value_type> g_state_map;

        // Functions
        auto entry_is_valid(const replica_state_table::entry& _e)
        {
            return _e.before && _e.after;
        } // entry_is_valid

        auto duplicate_and_acquire_data_object(const data_object_proxy& _obj) -> replica_state_table::doi_type
        {
            auto [dup, lm] = data_object::duplicate_data_object(_obj);
            // intentionally take ownership of memory
            lm.release();
            return dup.get();
        } // duplicate_and_acquire_data_object

        auto free_entry(replica_state_table::entry& _e, state_type _state) -> void
        {
            switch(_state) {
                case state_type::before:
                    freeAllDataObjInfo(_e.before);
                    break;

                case state_type::after:
                    freeAllDataObjInfo(_e.after);
                    break;

                default:
                    THROW(SYS_INVALID_INPUT_PARAM, fmt::format("invalid state type for free'ing entry"));
                    break;
            }
        } // free_entry

        auto reset_state_map() -> void
        {
            for (auto& r : g_state_map) {
                auto& e = r.second;
                free_entry(e, state_type::before);
                free_entry(e, state_type::after);
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

    auto replica_state_table::insert(const data_object_proxy& _obj) -> void
    {
        const key_type logical_path = _obj.logical_path().data();

        if (std::end(g_state_map) != g_state_map.find(logical_path)) {
            auto& rst = instance();
            rst.set(logical_path, _obj, state_type::before);
            rst.set(logical_path, _obj, state_type::after);
            return;
        }

        // duplicates structures, releases pointer to memory from lifetime manager, places in map
        auto before = duplicate_and_acquire_data_object(_obj);
        auto after = duplicate_and_acquire_data_object(_obj);

#if 1
        g_state_map[logical_path] = entry{.before = before, .after = after};

        if (!entry_is_valid(g_state_map.at(logical_path))) {
            g_state_map.erase(logical_path);

            THROW(SYS_INTERNAL_NULL_INPUT_ERR, fmt::format(
                "[{}:{}] - invalid before/after states at insertion time",
                __FUNCTION__, __LINE__));
        }
#else
        entry e{.before = before, .after = after};

        if (!entry_is_valid(e)) {
            THROW(SYS_INTERNAL_NULL_INPUT_ERR, fmt::format(
                "[{}:{}] - invalid before/after states at insertion time",
                __FUNCTION__, __LINE__));
        }

        g_state_map[logical_path] = e;
#endif
    } // insert

    auto replica_state_table::erase(const key_type& _logical_path) -> void
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::end(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
        }

        auto& e = itr->second;

        free_entry(e, state_type::before);

        free_entry(e, state_type::after);

        g_state_map.erase(_logical_path);
    } // erase

    auto replica_state_table::contains(const key_type& _logical_path) -> bool
    {
        for (auto&& [k, v] : g_state_map) {
            if (_logical_path == k) {
                return true;
            }
        }
        return false;
    } // contains

    auto replica_state_table::at(const key_type& _logical_path) -> replica_state_table::doi_pair_type
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
        }

        auto& e = itr->second;

        return {data_object_proxy{*e.before}, data_object_proxy{*e.after}};
    } // at

    auto replica_state_table::at(const key_type& _logical_path, const state_type _state) -> replica_state_table::data_object_proxy
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
        }

        auto& e = itr->second;

        switch(_state) {
            case state_type::before:
                return data_object_proxy{*e.before};
                break;

            case state_type::after:
                return data_object_proxy{*e.after};
                break;

            default:
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                    "invalid state type for getting replica info for [{}]", _logical_path));
                break;
        }
    } // at

    auto replica_state_table::set(const key_type& _logical_path, const data_object_proxy& _obj, const state_type _state) -> void
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("[{}] - no replica info held for [{}]", __FUNCTION__, _logical_path));
        }

        auto& e = itr->second;

        switch(_state) {
            case state_type::before:
                free_entry(e, state_type::before);
                e.before = duplicate_and_acquire_data_object(_obj);
                break;

            case state_type::after:
                free_entry(e, state_type::after);
                e.after = duplicate_and_acquire_data_object(_obj);
                break;

            default:
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                    "invalid state type for getting replica info for [{}]", _logical_path));
                break;
        }
    } // set

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
        }

        irods::log(LOG_DEBUG, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, input.dump()));

        return input;
    } // to_json

    auto replica_state_table::to_json(const key_type& _logical_path) -> nlohmann::json
    {
        auto& rst = replica_state_table::instance();

        const auto& [before, after] = rst.at(_logical_path);

        return replica_state_table::to_json(before, after);
    } // to_json
} // namespace irods::experimental

