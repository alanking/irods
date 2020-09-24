#ifndef IRODS_RESOLVE_RESOURCE_HIERARCHY_HPP
#define IRODS_RESOLVE_RESOURCE_HIERARCHY_HPP

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include <string_view>

struct RsComm;

namespace irods::experimental::resource
{
    /// \brief Determine the best resource for an operation
    ///
    /// Creates a data_object_proxy using the objPath from the dataObjInp_t.
    /// If nothing is found in the catalog, the data object has not been created yet.
    ///
    /// \param[in] _comm
    /// \param[in] _operation
    /// \param[in] _inp
    ///
    /// \returns A tuple with the dataObjInfo_t of the winning replica as well as the vote value
    ///
    /// \since 4.2.9
    auto resolve_resource_hierarchy(
        RsComm&             _comm,
        std::string_view    _operation,
        dataObjInp_t& _inp) -> data_object::data_object_proxy<dataObjInfo_t>;

    /// \brief Determine the best resource for an operation
    ///
    /// \param[in] _comm
    /// \param[in] _operation
    /// \param[in] _inp
    ///
    /// \returns A tuple with the dataObjInfo_t of the winning replica as well as the vote value
    ///
    /// \since 4.2.9
    auto resolve_resource_hierarchy(
        RsComm&             _comm,
        std::string_view    _operation,
        dataObjInp_t& _inp,
        data_object::data_object_proxy<dataObjInfo_t>& _obj)
        -> data_object::data_object_proxy<dataObjInfo_t>;
} // namespace irods::experimental::resource

#endif // IRODS_RESOLVE_RESOURCE_HIERARCHY_HPP
