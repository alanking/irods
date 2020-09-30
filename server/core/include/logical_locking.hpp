#ifndef IRODS_LOGICAL_LOCKING_HPP
#define IRODS_LOGICAL_LOCKING_HPP

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include "json.hpp"

struct RsComm;

namespace irods::experimental
{
    auto lock_data_object(
        RsComm& _comm,
        const dataObjInfo_t& _obj,
        const repl_status_t _lock_type) -> nlohmann::json;
} // namespace irods::experimental

#endif // IRODS_LOGICAL_LOCKING_HPP
