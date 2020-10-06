#ifndef IRODS_REPLICA_STATE_TABLE_HPP
#define IRODS_REPLICA_STATE_TABLE_HPP

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include "json.hpp"

#include <utility>
#include <string_view>

struct DataObjInfo;

namespace irods::experimental
{
    /// \brief Singleton which maintains a map of data objects in a start state and an end state
    ///
    /// Provides a partial implementation of a std::map interface for the internally managed
    /// global state map. The map has not been exposed in order to maintain control over the
    /// underlying data structures.
    ///
    /// \since 4.2.9
    class replica_state_table
    {
    public:
        // clang-format off
        using data_object_proxy = data_object::data_object_proxy<DataObjInfo>;
        using key_type          = std::string;
        using doi_type          = DataObjInfo*;
        using doi_pair_type     = std::pair<data_object_proxy, data_object_proxy>;
        // clang-format on

        // Prevent copying replica_state_table
        replica_state_table(const replica_state_table&) = delete;
        auto operator=(const replica_state_table&) -> replica_state_table& = delete;

        /// \brief Specify which version of the data object information to fetch from the map entry
        ///
        /// \since 4.2.9
        enum class state_type
        {
            before,
            after
        }; // enum class state_type

        /// \brief Holds data object information for before and after states
        ///
        /// \since 4.2.9
        struct entry
        {
            /// \var State of the data object fetched from the catalog before modifications are made
            doi_type before;

            /// \var Stores the most recent state of the replica as it changes throughout an operation
            doi_type after;
        }; // struct entry

        /// \brief Initialize the replica_state_table by making sure it is completely cleared out
        ///
        /// \since 4.2.9
        static auto init() -> void;

        /// \brief De-initialize the replica_state_table by making sure all managed memory is freed
        ///
        /// \since 4.2.9
        static auto deinit() -> void;

        /// \retval static Singleton instance
        ///
        /// \since 4.2.9
        static auto instance() noexcept -> replica_state_table&;

        /// \brief Create a new entry in the replica_state_table
        ///
        /// The created entry can be found by using the logical path of the passed-in data_object_proxy.
        /// If an entry with the indicated logical path already exists in the map, the information will be
        /// overwritten with a call to set_data_object_state on the before and after states.
        ///
        /// \param[in] _obj Initial data object state to serve as both "before" and "after" at the start
        ///
        /// \since 4.2.9
        auto insert(const data_object_proxy& _obj) -> void;

        /// \brief Erase replica_state_table entry indicated by _logical_path
        ///
        /// \param[in] _logical_path
        ///
        /// \throws irods::exception If no key matches _logical_path
        ///
        /// \since 4.2.9
        auto erase(const key_type& _logical_path) -> void;

        /// \param[in] _logical_path
        ///
        /// \returns bool
        /// \retval true if replica_state_table map contains key _logical_path
        /// \retval false if replica_state_table map does not contain key _logical_path
        ///
        /// \since 4.2.9
        auto contains(const key_type& _logical_path) -> bool;

        /// \brief Get the before or after state in the replica_state_table map for the given _logical_path
        ///
        /// \param[in] _logical_path
        /// \param[in] _state
        ///
        /// \returns doi_type&
        /// \retval Reference to the specified member of the entry at key _logical_path
        ///
        /// \throws irods::exception If _state is not a valid value or no entry exists for key _logical_path
        ///
        /// \since 4.2.9
        auto at(const key_type& _logical_path, const state_type _state) -> data_object_proxy;

        /// \brief Get the before and after state in the replica_state_table map for the given _logical_path
        ///
        /// \param[in] _logical_path
        ///
        /// \returns doi_pair_type
        /// \retval Pair of references to each member of the entry at key _logical_path
        ///
        /// \throws irods::exception If _state is not a valid value or no entry exists for key _logical_path
        ///
        /// \since 4.2.9
        auto at(const key_type& _logical_path) -> doi_pair_type;

        /// \brief Set the before or after state in the replica_state_table map for the given _logical_path
        ///
        /// Frees the existing data object information stored in the entry for the given state type and
        /// duplicates the passed-in data object information, storing it in the map.
        ///
        /// \param[in] _logical_path
        /// \param[in] _obj Data object information to set for the entry
        /// \param[in] _state
        ///
        /// \throws irods::exception If _state is not a valid value or no entry exists for key _logical_path
        ///
        /// \since 4.2.9
        auto set(
            const key_type& _logical_path,
            const data_object_proxy& _obj,
            const state_type _state = state_type::after) -> void;

        /// \brief Converts the provided data object information into a JSON structure for data_object_finalize
        ///
        /// \param[in] _before Data object information to use in the before state of the returned JSON
        /// \param[in] _after Data object information to use in the before state of the returned JSON
        ///
        /// \retval JSON object of the following form:
        ///     {
        ///         "data_id": <int>,
        ///         "replicas": [
        ///             {
        ///                 "before": {
        ///                     <r_data_main_column>: <string>,
        ///                     ...
        ///                 },
        ///                 "after": {
        ///                     <r_data_main_column>: <string>,
        ///                     ...
        ///                 }
        ///             },
        ///             ...
        ///         ]
        ///     }
        ///
        /// \since 4.2.9
        static auto to_json(
            const data_object_proxy& _before,
            const data_object_proxy& _after) -> nlohmann::json;

        /// \brief Converts the entry in key _logical_path to a JSON object for data_object_finalize
        ///
        /// Calls the (const data_object_proxy&, const data_object_proxy&) overload
        ///
        /// \param[in] _logical_path
        ///
        /// \retval JSON object of the following form:
        ///     {
        ///         "data_id": <int>,
        ///         "replicas": [
        ///             {
        ///                 "before": {
        ///                     <string>: <string>,
        ///                     ...
        ///                 },
        ///                 "after": {
        ///                     <string>: <string>,
        ///                     ...
        ///                 }
        ///             },
        ///             ...
        ///         ]
        ///     }
        ///
        /// \since 4.2.9
        static auto to_json(const key_type& _logical_path) -> nlohmann::json;

    private:
        // Disallow construction of the replica_state_table outside of member functions
        replica_state_table() = default;
    }; // class replica_state_table
} // namespace irods::experimental

#endif // IRODS_REPLICA_STATE_TABLE_HPP
