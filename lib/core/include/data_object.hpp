#ifndef IRODS_DATA_OBJECT_HPP
#define IRODS_DATA_OBJECT_HPP

#ifdef IRODS_REPLICA_ENABLE_SERVER_SIDE_API
    #define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
    #define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#else
    #undef IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
    #undef IRODS_QUERY_ENABLE_SERVER_SIDE_API
#endif

#include "filesystem.hpp"
#include "replica.hpp"

namespace irods::experimental::data_object
{
    /// \param[in] _comm connection object
    /// \param[in] _logical_path
    ///
    /// \throws irods::exception If query fails
    ///
    /// \retval true if qb.build returns results
    /// \retval false if qb.build returns no results
    ///
    /// \since 4.2.9
    template<typename rxComm>
    auto data_object_exists(
        rxComm& _comm,
        const irods::experimental::filesystem::path& _logical_path,
        const replica_number_type& _replica_number) -> bool
    {
        namespace replica = irods::experimental::replica;

        replica::detail::throw_if_replica_logical_path_is_invalid(_comm, _logical_path);

        query_builder qb;

        if (const auto zone = irods::experimental::filesystem::zone_name(_logical_path); zone) {
            qb.zone_hint(*zone);
        }

        const std::string qstr = fmt::format(
            "SELECT DATA_ID WHERE DATA_NAME = '{}' AND COLL_NAME = '{}'",
            _logical_path.object_name().c_str(), _logical_path.parent_path().c_str());

        return 0 != qb.build<rxComm>(_comm, qstr).size();
    } // data_object_exists
} // namespace irods::experimental::data_object

#endif // IRODS_DATA_OBJECT_HPP
