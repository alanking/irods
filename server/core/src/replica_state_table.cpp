#include "replica_state_table.hpp"

#include "fmt/format.h"

#include <map>

namespace irods::experimental
{
    namespace
    {
        // clang-format off
        using data_object_type  = replica_state_table::data_object_type;
        using maybe_data_object = replica_state_table::maybe_data_object;
        using state_type        = replica_state_table::state_type;
        using key_type          = replica_state_table::key_type;
        using value_type        = replica_state_table::entry;
        // clang-format on

        // Global Variables
        std::map<key_type, value_type> g_state_map;

        auto duplicate_and_acquire_data_object(const data_object_type& _obj) -> data_object_type
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

                if (e.before) {
                    freeAllDataObjInfo(e.before->get());
                }

                if (e.after) {
                    freeAllDataObjInfo(e.after->get());
                }
            }

            g_state_map.clear();
        } // reset_state_map
    } // anonymouse namespace

    auto replica_state_table::init()   -> void { reset_state_map(); }

    auto replica_state_table::deinit() -> void { reset_state_map(); }

    auto replica_state_table::instance() noexcept -> replica_state_table&
    {
        static replica_state_table instance;
        return instance;
    } // instance

    auto replica_state_table::create_entry(const data_object_type& _obj) -> data_object_type
    {
        const key_type& logical_path = _obj.logical_path();

        if (std::end(g_state_map) != g_state_map.find(logical_path)) {
            THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                "map already contains key [{}]", logical_path));
        }

        auto before = duplicate_and_acquire_data_object(_obj);

        entry e{before, std::nullopt};

        g_state_map[logical_path] = e;

        if (!e.before) {
            THROW(SYS_INTERNAL_ERR, "for some reason, before state was null");
        }

        return *(e.before);
    } // create_entry

    auto replica_state_table::erase_entry(const key_type& _logical_path) -> void
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("no replica info held for [{}]", _logical_path));
        }

        auto& e = itr->second;

        if (e.before) {
            freeAllDataObjInfo(e.before->get());
        }

        if (e.after) {
            freeAllDataObjInfo(e.after->get());
        }

        g_state_map.erase(_logical_path);
    } // erase_replica_info

    auto replica_state_table::contains(const key_type& _logical_path) -> bool
    {
        for (auto&& [k, v] : g_state_map) {
            if (_logical_path == k) {
                return true;
            }
        }
        return false;
    } // contains

    auto replica_state_table::get_data_object_state(
        const key_type& _logical_path,
        const state_type _state) -> maybe_data_object
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            irods::log(LOG_NOTICE, fmt::format("no replica info held for [{}]", _logical_path));
            return std::nullopt;
        }

        auto& e = itr->second;
        switch(_state) {
            case state_type::before:
                return e.before;

            case state_type::after:
                return e.after;

            default:
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                    "invalid state type for getting replica info for [{}]", _logical_path));
                break;
        }
    } // get_data_object_state

    auto replica_state_table::set_data_object_state(
        const key_type& _logical_path,
        const data_object_type& _obj,
        const state_type _state) -> void
    {
        auto itr = g_state_map.find(_logical_path);
        if (std::cend(g_state_map) == itr) {
            THROW(KEY_NOT_FOUND, fmt::format("no replica info held for [{}]", _logical_path));
        }

        auto& e = itr->second;
        switch(_state) {
            case state_type::before:
            {
                if (e.before) {
                    freeAllDataObjInfo(e.before->get());
                }
                e.before = duplicate_and_acquire_data_object(_obj);
                break;
            }

            case state_type::after:
            {
                if (e.after) {
                    freeAllDataObjInfo(e.after->get());
                }
                e.after = duplicate_and_acquire_data_object(_obj);
                break;
            }

            default:
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                    "invalid state type for getting replica info for [{}]", _logical_path));
                break;
        }
    } // set_data_object_state
} // namespace irods::experimental

