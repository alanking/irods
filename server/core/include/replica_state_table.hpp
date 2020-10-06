#ifndef IRODS_REPLICA_STATE_TABLE_HPP
#define IRODS_REPLICA_STATE_TABLE_HPP

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include <optional>
#include <string_view>

struct DataObjInfo;
struct RsComm;

namespace irods::experimental
{
    /// \brief Singleton which maintains a map of data objects in a start state and an end state
    ///
    /// \since 4.2.9
    class replica_state_table
    {
    public:
        // clang-format off
        using doi_type          = DataObjInfo;
        using data_object_type  = data_object::data_object_proxy<doi_type>;
        using maybe_data_object = std::optional<data_object_type>;
        using key_type          = std::string_view;
        // clang-format on

        enum class state_type
        {
            before,
            after
        };

        struct entry
        {
            maybe_data_object before;
            maybe_data_object after;
        }; // struct entry

        static auto init() -> void;

        static auto deinit() -> void;

        static auto instance() noexcept -> replica_state_table&;

        auto create_entry(const data_object_type& _obj) -> data_object_type;

        auto erase_entry(const key_type& _logical_path) -> void;

        auto contains(const key_type& _logical_path) -> bool;

        auto get_data_object_state(
            const key_type& _logical_path,
            state_type _state = state_type::before) -> maybe_data_object;

        auto set_data_object_state(
            const key_type& _logical_path,
            const data_object_type& _obj,
            state_type _state = state_type::after) -> data_object_type;

        replica_state_table(const replica_state_table&) = delete;
        auto operator=(const replica_state_table&) -> replica_state_table& = delete;

    private:
        replica_state_table() = default;
    }; // class replica_state_table
} // namespace irods::experimental

#endif // IRODS_REPLICA_STATE_TABLE_HPP
