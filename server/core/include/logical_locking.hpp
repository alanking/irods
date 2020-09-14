#ifndef IRODS_LOGICAL_LOCKING_HPP
#define IRODS_LOGICAL_LOCKING_HPP

#include "data_object_proxy.hpp"
#include "rcConnect.h"

#include "json.hpp"

namespace irods::experimental
{
    auto lock_data_object(
        rsComm_t& _comm,
        const dataObjInfo_t& _obj,
        const repl_status_t _lock_type) -> nlohmann::json;
} // namespace irods::experimental

#endif // IRODS_LOGICAL_LOCKING_HPP
