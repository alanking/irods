#ifndef IRODS_LOGICAL_LOCKING_HPP
#define IRODS_LOGICAL_LOCKING_HPP

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include <string_view>

struct DataObjInfo;
struct RsComm;

namespace irods
{
    auto lock_data_object(
        RsComm& _comm,
        irods::experimental::data_object::data_object_proxy<DataObjInfo>& _obj,
        std::string_view _operation) -> void;

    auto unlock_data_object(RsComm& _comm, std::string_view _logical_path) -> void;
} // namespace irods

#endif // IRODS_LOGICAL_LOCKING_HPP
