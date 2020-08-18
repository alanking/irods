#ifndef __IRODS_RESOURCE_REDIRECT_HPP__
#define __IRODS_RESOURCE_REDIRECT_HPP__

// =-=-=-=-=-=-=-
// irods includes
#include "rsGlobalExtern.hpp"

// =-=-=-=-=-=-=-
#include "irods_file_object.hpp"
#include "irods_log.hpp"

namespace irods {

    const std::string CREATE_OPERATION( "CREATE" );
    const std::string WRITE_OPERATION( "WRITE" );
    const std::string OPEN_OPERATION( "OPEN" );
    const std::string UNLINK_OPERATION( "UNLINK" );

    error resource_redirect(
        const std::string&, // requested operation to consider
        rsComm_t*,          // current agent connection
        dataObjInp_t*,      // data inp struct for data object in question
        std::string&,       // out going selected resource hierarchy
        rodsServerHost_t*&, // selected host for redirection if necessary
        int&,                // flag stating LOCAL_HOST or REMOTE_HOST
        dataObjInfo_t**    _data_obj_info = nullptr );

    irods::file_object_ptr resolve_resource_hierarchy(
        const std::string& _oper,
        rsComm_t&          _comm,
        dataObjInp_t&      _data_obj_inp,
        dataObjInfo_t**    _data_obj_info = nullptr);

    irods::file_object_ptr resolve_resource_hierarchy(
        rsComm_t&               _comm,
        const std::string&      _oper_in,
        dataObjInp_t&           _data_obj_inp,
        irods::file_object_ptr  _file_obj,
        const irods::error&     _fac_err);

}; // namespace irods

#endif // __IRODS_RESOURCE_REDIRECT_HPP__



