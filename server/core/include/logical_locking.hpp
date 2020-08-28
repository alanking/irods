#ifndef IRODS_LOGICAL_LOCKING_HPP
#define IRODS_LOGICAL_LOCKING_HPP

#include "irods_file_object.hpp"
#include "objInfo.h"
#include "rcConnect.h"

#include "json.hpp"

namespace irods::experimental {

    nlohmann::json lock_data_object(
        rsComm_t& _comm,
        const irods::file_object_ptr _obj,
        const repl_status_t _lock_type);

    nlohmann::json sync_replica_states_with_catalog(
        rsComm_t& _comm,
        const irods::file_object_ptr _obj);

} // namespace irods::experimental

#endif // IRODS_LOGICAL_LOCKING_HPP
