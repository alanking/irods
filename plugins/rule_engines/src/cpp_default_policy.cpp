// =-=-=-=-=-=-=-
// irods includes
#include "irods/msParam.h"
#include "irods/private/re/reGlobalsExtern.hpp"
#include "irods/generalAdmin.h"
#include "irods/miscServerFunct.hpp"

// =-=-=-=-=-=-=-
#include "irods/irods_resource_plugin.hpp"
#include "irods/irods_file_object.hpp"
#include "irods/irods_physical_object.hpp"
#include "irods/irods_collection_object.hpp"
#include "irods/irods_string_tokenize.hpp"
#include "irods/irods_hierarchy_parser.hpp"
#include "irods/irods_resource_redirect.hpp"
#include "irods/irods_stacktrace.hpp"
#include "irods/irods_re_plugin.hpp"
#include "irods/irods_re_ruleexistshelper.hpp"
#include "irods/irods_re_structs.hpp"

#include "irods/irods_hasher_factory.hpp"
#include "irods/MD5Strategy.hpp"

#include <fmt/format.h>

// =-=-=-=-=-=-=-
// stl includes
#include <iostream>
#include <sstream>
#include <vector>
#include <string>

// =-=-=-=-=-=-=-
// boost includes
#include <boost/lexical_cast.hpp>
#include <boost/function.hpp>
#include <boost/any.hpp>

#include "irods/private/re/configuration.hpp"
#include "irods/irods_server_properties.hpp"
#include <nlohmann/json.hpp>

#define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include "irods/query_builder.hpp"

#define STATIC_PEP(NAME) static_policy_enforcement_points[#NAME] = NAME

using json = nlohmann::json;

typedef std::function< irods::error (irods::callback, std::list<boost::any>&) > pep_opr_t;

static std::map< std::string, pep_opr_t > static_policy_enforcement_points;

const std::string DEFAULT_RULE_REGEX = "ac[^ ]*";

ruleExecInfo_t& get_rei(irods::callback& _cb) {
    ruleExecInfo_t* rei{nullptr};
    irods::error ret{_cb(std::string("unsafe_ms_ctx"), &rei)};
    if (!ret.ok()) {
        THROW(ret.code(), "failed to get rei");
    }

    return *rei;
}

rsComm_t& get_rs_comm(ruleExecInfo_t& _rei) {
    rsComm_t* rs_comm{nullptr};
    rs_comm = _rei.rsComm;

    if (!rs_comm) {
        THROW(-1, "null rs_comm");
    }

    return *rs_comm;
}

userInfo_t get_uoio(ruleExecInfo_t& _rei) {
    userInfo_t* uoio{nullptr};
    uoio = _rei.uoio;

    if (!uoio) {
        THROW(-1, "null other user info object");
    }

    return *uoio;
}

static std::string get_string_array_from_array( const boost::any& _array ) {
    std::string str_array;
    try {
        for( const auto& elem : boost::any_cast< const std::vector< boost::any >& >( _array ) ) {
            try {
                str_array += boost::any_cast< const std::string& >( elem );
            }
            catch ( const boost::bad_any_cast& ) {
                rodsLog(
                    LOG_ERROR,
                    "%s - failed to cast rule base file name entry to string",
                    __PRETTY_FUNCTION__ );
                continue;
            }

            str_array += ",";
        } // for

        str_array = str_array.substr( 0, str_array.size() - 1 );
        return str_array;
    } catch ( const boost::bad_any_cast& ) {
        THROW(
            INVALID_ANY_CAST,
            "failed to any_cast to vector" );
    }
}

// =-=-=-=-=-=-=-
// implementations of static policy enforcement points from legacy core.re

irods::error printHello( irods::callback _cb, std::list<boost::any>& ) {
// printHello { print_hello; }
    return _cb(std::string("print_hello"));
}

irods::error acPreConnect( irods::callback _cb, std::list<boost::any>& _params ) {
// acPreConnect(*OUT) { *OUT="CS_NEG_DONT_CARE"; }
    for( auto itr : _params ) {
        if(itr.type() == typeid(std::string*)) {
            try {
                *boost::any_cast<std::string*>(itr) = "CS_NEG_REFUSE";
            } catch (const boost::bad_any_cast& e) {
                rodsLog(LOG_ERROR, "Bad any cast in acPreConnect, [%s]", e.what());
                return ERROR(
                    INVALID_ANY_CAST,
                    "Bad any_cast in acPreConnect()" );
            }
        }
    }

    return SUCCESS();
}

irods::error acCreateUser( irods::callback _cb, std::list<boost::any>& ) {
/*
acCreateUser {
    acPreProcForCreateUser;
    acCreateUserF1;
    acPostProcForCreateUser; }
acCreateUserF1 {
    ON($otherUserName == "anonymous") {
        msiCreateUser ::: msiRollback;
        msiCommit; } }
acCreateUserF1 {
    msiCreateUser ::: msiRollback;
    acCreateDefaultCollections ::: msiRollback;
    msiAddUserToGroup("public") ::: msiRollback;
    msiCommit; }
*/
    irods::error ret = _cb(std::string("acPreProcForCreateUser"));

    ret = _cb(std::string("msiCreateUser"));
    if( !ret.ok() ) {
        _cb(std::string("msiRollback"));
        return ret;
    }

    std::string other_user_name;

    try {
        ruleExecInfo_t& rei{get_rei(_cb)};
        userInfo_t other_user_info = get_uoio(rei);

        other_user_name = other_user_info.userName;
    } catch ( const irods::exception& e ) {
        irods::log(e);
        return ERROR(e.code(), "irods exception in acCreateUser");
    }

    if (other_user_name != "anonymous") {
        ret = _cb(std::string("acCreateDefaultCollections"));

        ret = _cb(std::string("msiAddUserToGroup"), std::string("public"));
        if ( !ret.ok() ) {
            _cb(std::string("msiRollback"));
            return ret;
        }
    }

    ret = _cb(std::string("msiCommit"));

    ret = _cb(std::string("acPostProcForCreateUser"));

    return ret;
}

irods::error acCreateDefaultCollections( irods::callback _cb, std::list<boost::any>& ) {
// acCreateDefaultCollections { acCreateUserZoneCollections; }
    irods::error ret = _cb(std::string("acCreateUserZoneCollections"));
    return ret;
}

irods::error acCreateUserZoneCollections( irods::callback _cb, std::list<boost::any>& ) {
//  acCreateUserZoneCollections {
//  acCreateCollByAdmin("/"++$rodsZoneProxy++"/home", $otherUserName);
//  acCreateCollByAdmin("/"++$rodsZoneProxy++"/trash/home", $otherUserName); }
    std::string rods_zone_proxy;
    std::string other_user_name;

    try {
        ruleExecInfo_t& rei{get_rei(_cb)};
        rsComm_t& rs_comm{get_rs_comm(rei)};

        userInfo_t user_info;
        user_info = rs_comm.proxyUser;

        userInfo_t other_user_info = get_uoio(rei);

        rods_zone_proxy = user_info.rodsZone;
        other_user_name = other_user_info.userName;
    } catch ( const irods::exception& e ) {
        irods::log(e);
        return ERROR(e.code(), "irods exception in acCreateDefaultCollections");
    }

    std::string home_coll = "/" + rods_zone_proxy + "/home";
    std::string trash_coll = "/" + rods_zone_proxy + "/trash/home";

    irods::error ret = _cb(std::string("acCreateCollByAdmin"), home_coll, other_user_name);
    ret = _cb(std::string("acCreateCollByAdmin"), trash_coll, other_user_name);
    return ret;
}

irods::error acCreateCollByAdmin( irods::callback _cb, std::list<boost::any>& _params) {
//  acCreateCollByAdmin(*parColl, *childColl) {
//    msiCreateCollByAdmin(*parColl, *childColl); }
    std::string parent_coll;
    std::string child_coll;
    int i = 0;
    for (auto& param: _params) {
        try {
            std::string tmp = boost::any_cast<std::string>(param);

            if (i == 0) {
                parent_coll = tmp;
            } else if (i == 1) {
                child_coll = tmp;
            }

            i++;
        } catch (const boost::bad_any_cast& e) {
            rodsLog(LOG_ERROR, "Bad any cast on param %d in acCreateCollByAdmin", i);
        }
    }

    irods::error ret = _cb(std::string("msiCreateCollByAdmin"), parent_coll, child_coll);
    return ret;
}

irods::error acDeleteUser( irods::callback _cb, std::list<boost::any>& ) {
/*
acDeleteUser {
    acPreProcForDeleteUser;
    acDeleteUserF1;
    acPostProcForDeleteUser; }
acDeleteUserF1 {
    acDeleteDefaultCollections ::: msiRollback;
    msiDeleteUser ::: msiRollback;
    msiCommit; }
*/
    irods::error ret = _cb(std::string("acPreProcForDeleteUser"));

    ret = _cb(std::string("acDeleteDefaultCollections"));
    if( !ret.ok() ) {
        _cb(std::string("msiRollback"));
        return ret;
    }

    ret = _cb(std::string("msiDeleteUser"));
    if( !ret.ok() ) {
        _cb(std::string("msiRollback"));
        return ret;
    }

    ret = _cb(std::string("msiCommit"));

    ret = _cb(std::string("acPostProcForDeleteUser"));

    return ret;
}

irods::error acDeleteDefaultCollections( irods::callback _cb, std::list<boost::any>& ) {
//acDeleteDefaultCollections {
//    acDeleteUserZoneCollections; }
    irods::error ret = _cb(std::string("acDeleteUserZoneCollections"));
    return ret;
}

irods::error acDeleteUserZoneCollections( irods::callback _cb, std::list<boost::any>& ) {
//acDeleteUserZoneCollections {
//    acDeleteCollByAdminIfPresent("/"++$rodsZoneProxy++"/home",$otherUserName);
//    acDeleteCollByAdminIfPresent("/"++$rodsZoneProxy++"/trash/home",$otherUserName); }
    std::string rods_zone_proxy;
    std::string other_user_name;

    try {
        ruleExecInfo_t& rei{get_rei(_cb)};
        rsComm_t& rs_comm{get_rs_comm(rei)};

        userInfo_t user_info;
        user_info = rs_comm.proxyUser;

        userInfo_t other_user_info = get_uoio(rei);

        rods_zone_proxy = user_info.rodsZone;
        other_user_name = other_user_info.userName;
    } catch ( const irods::exception& e ) {
        irods::log(e);
        return ERROR(e.code(), "irods exception in acDeleteDefaultCollections");
    }

    std::string home_coll = "/" + rods_zone_proxy + "/home";
    std::string trash_coll = "/" + rods_zone_proxy + "/trash/home";

    irods::error ret = _cb(std::string("acDeleteCollByAdminIfPresent"), home_coll, other_user_name);
    ret = _cb(std::string("acDeleteCollByAdminIfPresent"), trash_coll, other_user_name);
    return ret;
}

irods::error acDeleteCollByAdminIfPresent( irods::callback _cb, std::list<boost::any>& _params ) {
//acDeleteCollByAdminIfPresent(*parColl, *childColl) {
//    *status=errormsg(msiDeleteCollByAdmin(*parColl,*childColl), *msg);
//    if (*status != 0 && *status != -808000) {
//        failmsg(*status,*msg) } }
    std::string parent_coll;
    std::string child_coll;
    int i = 0;
    for (auto& param: _params) {
        try {
            std::string tmp = boost::any_cast<std::string>(param);

            if (i == 0) {
                parent_coll = tmp;
            } else if (i == 1) {
                child_coll = tmp;
            }

            i++;
        } catch (const boost::bad_any_cast& e) {
            rodsLog(LOG_ERROR, "Bad any cast on param [%d] in acDeleteCollByAdminIfPresent", i);
        }
    }


    irods::error ret = _cb(std::string("acDeleteCollByAdmin"), parent_coll, child_coll);
    if (!ret.ok() && ret.code() != CAT_NO_ROWS_FOUND) {
        return ret;
    }

    return SUCCESS();
}

irods::error acDeleteCollByAdmin( irods::callback _cb, std::list<boost::any>& _params) {
//acDeleteCollByAdmin(*parColl,*childColl) {
//    msiDeleteCollByAdmin(*parColl,*childColl); }
    std::string parent_coll;
    std::string child_coll;
    int i = 0;
    for (auto& param: _params) {
        try {
            std::string tmp = boost::any_cast<std::string>(param);

            if (i == 0) {
                parent_coll = tmp;
            } else if (i == 1) {
                child_coll = tmp;
            }

            i++;
        } catch (const boost::bad_any_cast& e) {
            rodsLog(LOG_ERROR, "Bad any cast on param [%d] in acDeleteCollByAdmin", i);
        }
    }

    irods::error ret = _cb(std::string("msiDeleteCollByAdmin"), parent_coll, child_coll);
    return ret;
}

irods::error acRenameLocalZone( irods::callback _cb, std::list<boost::any>& ) {
//  msiRenameLocalZoneCollection ::: msiRollback;
//  msiRenameLocalZone ::: msiRenameLocalZone;
//  msiCommit;
   irods::error ret = _cb(std::string("msiRenameLocalZoneCollection"));
    if( !ret.ok() ) {
        _cb(std::string("msiRollback"));
        return ret;
    }

    ret = _cb(std::string("msiRenameLocalZone"));
    if( !ret.ok() ) {
        _cb(std::string("msiRollback"));
        return ret;
    }

    ret = _cb(std::string("msiCommit"));

    return ret;
}

irods::error acGetUserByDN( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acTicketPolicy( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acCheckPasswordStrength( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acSetRescSchemeForCreate( irods::callback _cb, std::list<boost::any>& ) {
//msiSetDefaultResc("demoResc","null");
/*
    props.capture_if_needed();
    irods::server_properties& props = irods::server_properties::instance();
    irods::error ret = props.get_property<std::string>("default_resource_name", resc_name);
    if( !ret.ok() ) {
        resc_name = "demoResc";
    }
*/
    std::string resc_name = "demoResc";
    try {
        resc_name = irods::server_properties::instance().get_property<std::string>("default_resource_name");
    } catch ( const irods::exception& ) {
        rodsLog(
            LOG_NOTICE,
            "No default_resource_name in server properties - using 'demoResc'");
    }

    return _cb(std::string("msiSetDefaultResc"), resc_name, std::string("null"));
}

irods::error acSetRescSchemeForRepl( irods::callback _cb, std::list<boost::any>& ) {
//msiSetDefaultResc("demoResc","null");
/*
    irods::server_properties& props = irods::server_properties::instance();
    props.capture_if_needed();
    std::string resc_name;
    irods::error ret = props.get_property<std::string>("default_resource_name", resc_name);
    if( !ret.ok() ) {
        resc_name = "demoResc";
    }
*/
    std::string resc_name = "demoResc";
    try {
        resc_name = irods::server_properties::instance().get_property<std::string>("default_resource_name");
    } catch ( const irods::exception& ) {
        rodsLog(
            LOG_NOTICE,
            "No default_resource_name in server properties - using 'demoResc'");
    }

    return _cb(std::string("msiSetDefaultResc"), resc_name, std::string("null"));
}

irods::error acPreprocForDataObjOpen( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acSetMultiReplPerResc( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForPut( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForCopy( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForFilePathReg( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForCreate( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForOpen( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForPhymv( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForRepl( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acSetNumThreads( irods::callback _cb, std::list<boost::any>& ) {
//msiSetNumThreads("default","64","default");
    return _cb(std::string("msiSetNumThreads"), std::string("default"), std::string("64"), std::string("default"));
}

irods::error acDataDeletePolicy( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForDelete( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acSetChkFilePathPerm( irods::callback _cb, std::list<boost::any>& ) {
//msiSetChkFilePathPerm("disallowPathReg");
    return _cb(std::string("msiSetChkFilePathPerm"), std::string("disallowPathReg"));
}

irods::error acTrashPolicy( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acSetPublicUserPolicy( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acChkHostAccessControl( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acSetVaultPathPolicy( irods::callback _cb, std::list<boost::any>& ) {
    //msiSetGraftPathScheme("no","1");
    return _cb(std::string("msiSetGraftPathScheme"), std::string("no"), std::string("1"));
}

irods::error acPreprocForCollCreate( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForCollCreate( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreprocForRmColl( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForRmColl( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForModifyUser( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForModifyUser( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForModifyAVUMetadata( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForModifyAVUMetadata( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForCreateUser( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForCreateUser( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForDeleteUser( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForDeleteUser( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForCreateResource( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForCreateResource( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForCreateToken( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForCreateToken( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForModifyUserGroup( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForModifyUserGroup( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForDeleteResource( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForDeleteResource( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForDeleteToken( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForDeleteToken( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForModifyResource( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForModifyResource( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForModifyCollMeta( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForModifyCollMeta( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForModifyDataObjMeta( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForModifyDataObjMeta( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForModifyAccessControl( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForModifyAccessControl( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForObjRename( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForObjRename( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForGenQuery( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForGenQuery( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acRescQuotaPolicy( irods::callback _cb, std::list<boost::any>& ) {
    return _cb(std::string("msiSetRescQuotaPolicy"), std::string("off"));
}

irods::error acBulkPutPostProcPolicy ( irods::callback _cb, std::list<boost::any>& ) {
    return _cb(std::string("msiSetBulkPutPostProcPolicy"), std::string("off"));
}

irods::error acPostProcForTarFileReg( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForDataObjWrite( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForDataObjRead( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForExecCmd( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForServerPortal( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForServerPortal( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPreProcForWriteSessionVariable( irods::callback, std::list<boost::any>& _params ) {
//acPreProcForWriteSessionVariable(*var) {
//  ON(*var == "status") {
//    succeed;
//  }
//  or {
//    failmsg(-1, "Update session variable $*var not allowed!");
//  }
//}
    std::string session_var;
    int i = 0;
    for (auto& param: _params) {
        try {
            std::string tmp = boost::any_cast<std::string>(param);

            if (i == 0) {
                session_var = tmp;
                break;
            }

            i++;
        } catch (const boost::bad_any_cast& e) {
            rodsLog(LOG_ERROR, "Bad any cast on param [%d] in acPreProcForWriteSessionVar", i);
        }
    }

    if (session_var == "status") {
        return SUCCESS();
    } else {
        return ERROR(SYS_INVALID_INPUT_PARAM, "Updating session variable $" +  session_var + " is not allowed");
    }
}

irods::error acPostProcForParallelTransferReceived( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error acPostProcForDataCopyReceived( irods::callback, std::list<boost::any>& ) {
    return SUCCESS();
}

irods::error start(irods::default_re_ctx& _u, const std::string& _instance_name) {
    (void) _u;
    STATIC_PEP(printHello);
    STATIC_PEP(acPreConnect);
    STATIC_PEP(acCreateUser);
    STATIC_PEP(acCreateDefaultCollections);
    STATIC_PEP(acCreateUserZoneCollections);
    STATIC_PEP(acCreateCollByAdmin);
    STATIC_PEP(acDeleteUser);
    STATIC_PEP(acDeleteDefaultCollections);
    STATIC_PEP(acDeleteUserZoneCollections);
    STATIC_PEP(acDeleteCollByAdminIfPresent);
    STATIC_PEP(acDeleteCollByAdmin);
    STATIC_PEP(acRenameLocalZone);
    STATIC_PEP(acGetUserByDN);
    STATIC_PEP(acTicketPolicy);
    STATIC_PEP(acCheckPasswordStrength);
    STATIC_PEP(acSetRescSchemeForCreate);
    STATIC_PEP(acSetRescSchemeForRepl);
    STATIC_PEP(acPreprocForDataObjOpen);
    STATIC_PEP(acSetMultiReplPerResc);
    STATIC_PEP(acPostProcForPut);
    STATIC_PEP(acPostProcForCopy);
    STATIC_PEP(acPostProcForFilePathReg);
    STATIC_PEP(acPostProcForCreate);
    STATIC_PEP(acPostProcForOpen);
    STATIC_PEP(acPostProcForPhymv);
    STATIC_PEP(acPostProcForRepl);
    STATIC_PEP(acSetNumThreads);
    STATIC_PEP(acDataDeletePolicy);
    STATIC_PEP(acPostProcForDelete);
    STATIC_PEP(acSetChkFilePathPerm);
    STATIC_PEP(acTrashPolicy);
    STATIC_PEP(acSetPublicUserPolicy);
    STATIC_PEP(acChkHostAccessControl);
    STATIC_PEP(acSetVaultPathPolicy);
    STATIC_PEP(acPreprocForCollCreate);
    STATIC_PEP(acPostProcForCollCreate);
    STATIC_PEP(acPreprocForRmColl);
    STATIC_PEP(acPostProcForRmColl);
    STATIC_PEP(acPreProcForModifyUser);
    STATIC_PEP(acPostProcForModifyUser);
    STATIC_PEP(acPreProcForModifyAVUMetadata);
    STATIC_PEP(acPostProcForModifyAVUMetadata);
    STATIC_PEP(acPreProcForCreateUser);
    STATIC_PEP(acPostProcForCreateUser);
    STATIC_PEP(acPreProcForDeleteUser);
    STATIC_PEP(acPostProcForDeleteUser);
    STATIC_PEP(acPreProcForCreateResource);
    STATIC_PEP(acPostProcForCreateResource);
    STATIC_PEP(acPreProcForCreateToken);
    STATIC_PEP(acPostProcForCreateToken);
    STATIC_PEP(acPreProcForModifyUserGroup);
    STATIC_PEP(acPostProcForModifyUserGroup);
    STATIC_PEP(acPreProcForDeleteResource);
    STATIC_PEP(acPostProcForDeleteResource);
    STATIC_PEP(acPreProcForDeleteToken);
    STATIC_PEP(acPostProcForDeleteToken);
    STATIC_PEP(acPreProcForModifyResource);
    STATIC_PEP(acPostProcForModifyResource);
    STATIC_PEP(acPreProcForModifyCollMeta);
    STATIC_PEP(acPostProcForModifyCollMeta);
    STATIC_PEP(acPreProcForModifyDataObjMeta);
    STATIC_PEP(acPostProcForModifyDataObjMeta);
    STATIC_PEP(acPreProcForModifyAccessControl);
    STATIC_PEP(acPostProcForModifyAccessControl);
    STATIC_PEP(acPreProcForObjRename);
    STATIC_PEP(acPostProcForObjRename);
    STATIC_PEP(acPreProcForGenQuery);
    STATIC_PEP(acPostProcForGenQuery);
    STATIC_PEP(acRescQuotaPolicy);
    STATIC_PEP(acBulkPutPostProcPolicy);
    STATIC_PEP(acPostProcForTarFileReg);
    STATIC_PEP(acPostProcForDataObjWrite);
    STATIC_PEP(acPostProcForDataObjRead);
    STATIC_PEP(acPreProcForExecCmd);
    STATIC_PEP(acPreProcForServerPortal);
    STATIC_PEP(acPostProcForServerPortal);
    STATIC_PEP(acPreProcForWriteSessionVariable);
    STATIC_PEP(acPostProcForParallelTransferReceived);
    STATIC_PEP(acPostProcForDataCopyReceived);

    // Can just do it, since this rule engine is pre-compiled
    RuleExistsHelper::Instance()->registerRuleRegex( DEFAULT_RULE_REGEX );
    RuleExistsHelper::Instance()->registerRuleRegex( "irods_policy_e.*" );

    return SUCCESS();

} // start

irods::error stop(irods::default_re_ctx& _u, const std::string&) {
    (void) _u;
    return SUCCESS();
}

int _delayExec(const char* rule, const char* recov, const char* condition, ruleExecInfo_t*);

namespace
{
    auto rule_is_irods_policy_enqueue_rule(const std::string& _rn) -> bool
    {
        auto b =  "irods_policy_enqueue_rule" == _rn;
        return b;
    }

    auto rule_is_irods_policy_execute_rule(const std::string& _rn) -> bool
    {
        return "irods_policy_execute_rule" == _rn;
    }

    auto rule_is_irods_policy_rule(const std::string& _rn) -> bool
    {
        auto b = rule_is_irods_policy_enqueue_rule(_rn) ||
                 rule_is_irods_policy_execute_rule(_rn);
        return b;
    }

    auto collapse_error_stack(rError_t& _error) -> std::string
    {
        std::stringstream ss;
        for(int i = 0; i < _error.len; ++i) {
            rErrMsg_t* err_msg = _error.errMsg[i];
            if(err_msg->status != STDOUT_STATUS) {
                ss << "status: " << err_msg->status << " ";
            }

            ss << err_msg->msg << " - ";
        }

        return ss.str();

    } // collapse_error_stack

    void invoke_policy(
        ruleExecInfo_t*        _rei,
        const std::string&     _action,
        std::list<boost::any>& _args)
    {
        irods::rule_engine_context_manager<
            irods::unit,
            ruleExecInfo_t*,
            irods::AUDIT_RULE> re_ctx_mgr(
                    irods::re_plugin_globals->global_re_mgr,
                    _rei);
        irods::error err = re_ctx_mgr.exec_rule(_action, irods::unpack(_args));
        if(!err.ok()) {
            if(_rei->status < 0) {
                std::string msg = collapse_error_stack(_rei->rsComm->rError);
                THROW(_rei->status, msg);
            }

            THROW(err.code(), err.result());
        }

    } // invoke_policy

    auto rule_is_not_already_enqueued(rsComm_t* comm, const std::string& md5)
    {
        auto qs = fmt::format("SELECT RULE_EXEC_NAME WHERE RULE_EXEC_NAME LIKE '%{}%'", md5);

        irods::experimental::query_builder qb;
        return qb.build(*comm, qs).size() == 0;

    } // rule_is_not_already_enqueued

    auto demangle(const char* name) -> std::string
    {
        int status{};
        std::unique_ptr<char, void(*)(void*)> res {
            abi::__cxa_demangle(name, NULL, NULL, &status),
                std::free
        };

        return (status==0) ? res.get() : name;

    } // demangle

    auto enqueue_rule(ruleExecInfo_t* _rei, const json& _p) -> irods::error
    {
        auto params = _p;

        irods::Hasher hasher;
        irods::getHasher( irods::MD5_NAME, hasher );
        hasher.update(params.dump().c_str());
        std::string digest;
        hasher.digest(digest);

        if(rule_is_not_already_enqueued(_rei->rsComm, digest)) {
            params["md5"] = digest;

            const auto delay_cond = params.contains("delay_conditions")
                                    ? params.at("delay_conditions").get<std::string>()
                                    : std::string{};

            const auto err = _delayExec(params.dump().c_str(), "",
                                        delay_cond.c_str(), _rei);
            if(err < 0) {
                return ERROR(err, "delayExec failed");
            }
        }

        return SUCCESS();

    } // enqueue_rule

    auto execute_rule(ruleExecInfo_t* _rei, json& _rule) -> irods::error
    {
        if(!_rule.contains("parameters")) {
            return ERROR(
                       SYS_NOT_SUPPORTED,
                       "exec_rule_text : parameters is empty");
        }

        auto pm = _rule.at("parameters");

        auto p2i = pm.at("policy_to_invoke").get<std::string>();

        std::string ps = pm.contains("parameters")
                         ? pm.at("parameters").dump()
                         : _rule.dump();
        std::string cs = pm.contains("configuration")
                         ? pm.at("configuration").dump()
                         : std::string{};
        std::string ov{};

        std::list<boost::any> arguments;
        arguments.push_back(boost::any(&ps));
        arguments.push_back(boost::any(&cs));
        arguments.push_back(boost::any(&ov));
        invoke_policy(_rei, p2i, arguments);

        return SUCCESS();

    } // execute_rule

} // namespace

irods::error rule_exists(irods::default_re_ctx&, const std::string& _rn, bool& _ret)
{
    _ret = ( static_policy_enforcement_points.find(_rn) !=
             static_policy_enforcement_points.end()     ||
             rule_is_irods_policy_rule(_rn) );
    return SUCCESS();
}

irods::error list_rules(irods::default_re_ctx&, std::vector<std::string>& rule_vec)
{
    for (auto& map_entry : static_policy_enforcement_points) {
       rule_vec.push_back(map_entry.first);
    }

    rule_vec.push_back("irods_policy_enqueue_rule");
    rule_vec.push_back("irods_policy_execute_rule");

    return SUCCESS();
}

irods::error exec_rule(
    irods::default_re_ctx&,
    const std::string&     _rn,
    std::list<boost::any>& _ps,
    irods::callback        _eff_hdlr)
{
    ruleExecInfo_t * rei{};
    irods::error err;

    if(!(err = _eff_hdlr("unsafe_ms_ctx", &rei)).ok()) {
        return err;
    }

    if(rule_is_irods_policy_enqueue_rule(_rn)) {
        auto* p = boost::any_cast<std::string*>(*_ps.begin());
        return enqueue_rule(rei, json::parse(*p));
    }

    if(static_policy_enforcement_points.find(_rn) !=
       static_policy_enforcement_points.end() ) {
       return static_policy_enforcement_points[_rn](_eff_hdlr,_ps);
    }
    else {
        rodsLog(
            LOG_ERROR,
            "[%s] not defined in default rule engine",
            _rn.c_str() );
        return SUCCESS();
    }
} // exec_rule

irods::error exec_rule_text(
    irods::default_re_ctx&,
    const std::string& _rule_text,
    msParamArray_t*    _ms_params,
    const std::string& _out_desc,
    irods::callback    _eff_hdlr)
{
    ruleExecInfo_t* rei{};
    irods::error    err;
    if(!(err = _eff_hdlr("unsafe_ms_ctx", &rei)).ok()) {
        return err;
    }

    try {
        // skip the first line: @external
        std::string rule_text{_rule_text};
        if(_rule_text.find("@external") != std::string::npos) {
            rule_text = _rule_text.substr(10);
        }

        auto rule = json::parse(rule_text);

        if(!rule.contains("policy_to_invoke")) {
            return ERROR(
                       SYS_NOT_SUPPORTED,
                       "exec_rule_text : policy to invoke is empty");
        }

        auto p2i = rule.at("policy_to_invoke").get<std::string>();

        if(rule_is_irods_policy_enqueue_rule(p2i)) {
            return enqueue_rule(rei, rule.at("parameters"));
        }
        else if(rule_is_irods_policy_execute_rule(p2i)) {
            return execute_rule(rei, rule);
        }
    }
    catch(const json::exception& e) {
        addRErrorMsg(
            &rei->rsComm->rError,
            SYS_INVALID_INPUT_PARAM,
            e.what());
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   e.what());
    }
    catch(const irods::exception& e) {
        addRErrorMsg(
            &rei->rsComm->rError,
            SYS_INVALID_INPUT_PARAM,
            e.what());
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   e.what());
    }
    catch(const std::exception& e) {
        addRErrorMsg(
            &rei->rsComm->rError,
            SYS_INVALID_INPUT_PARAM,
            e.what());
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   e.what());
    }

    return SUCCESS();//CODE(RULE_ENGINE_CONTINUE);

} // exec_rule_text

irods::error exec_rule_expression(
    irods::default_re_ctx&,
    const std::string& _rule_text,
    msParamArray_t*    _ms_params,
    irods::callback    _eff_hdlr)
{
    using json = nlohmann::json;

    ruleExecInfo_t* rei{};
    irods::error    err;
    if(!(err = _eff_hdlr("unsafe_ms_ctx", &rei)).ok()) {
        return err;
    }

    try {
        json r{json::parse(_rule_text)};

        if(!r.contains("policy_to_invoke")) {
            return ERROR(SYS_NOT_SUPPORTED,
                         "exec_rule_expression is not supported");
        }

        std::string p2i = r.at("policy_to_invoke");

        if(rule_is_irods_policy_execute_rule(p2i)) {
            return execute_rule(rei, r);
        }

        return ERROR(SYS_NOT_SUPPORTED,
                     "exec_rule_expression is not supported");
    }
    catch(const json::exception& e) {
        addRErrorMsg(
            &rei->rsComm->rError,
            SYS_INVALID_INPUT_PARAM,
            e.what());
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   e.what());
    }
    catch(const irods::exception& e) {
        addRErrorMsg(
            &rei->rsComm->rError,
            SYS_INVALID_INPUT_PARAM,
            e.what());
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   e.what());
    }
    catch(const std::exception& e) {
        addRErrorMsg(
            &rei->rsComm->rError,
            SYS_INVALID_INPUT_PARAM,
            e.what());
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   e.what());
    }

    return SUCCESS();

} // exec_rule_expression

extern "C"
irods::pluggable_rule_engine<irods::default_re_ctx>* plugin_factory( const std::string& _inst_name,
                                 const std::string& _context ) {
    irods::pluggable_rule_engine<irods::default_re_ctx>* re = new irods::pluggable_rule_engine<irods::default_re_ctx>( _inst_name , _context);

    const auto no_op = [](irods::default_re_ctx&, const std::string&) -> irods::error { return SUCCESS(); };

    re->add_operation("setup", std::function{no_op});
    re->add_operation("teardown", std::function{no_op});

    re->add_operation( "start",
            std::function<irods::error(irods::default_re_ctx&, const std::string&)>( start ) );

    re->add_operation( "stop",
            std::function<irods::error(irods::default_re_ctx&, const std::string&)>( stop ) );

    re->add_operation( "rule_exists",
            std::function<irods::error(irods::default_re_ctx&, const std::string&, bool&)>( rule_exists ) );

    re->add_operation( "list_rules",
            std::function<irods::error(irods::default_re_ctx&, std::vector<std::string>&)>( list_rules ) );

    re->add_operation( "exec_rule",
            std::function<irods::error(irods::default_re_ctx&,const std::string&,std::list<boost::any>&,irods::callback)>( exec_rule ) );

    re->add_operation( "exec_rule_text",
            std::function<irods::error(irods::default_re_ctx&,const std::string&,msParamArray_t*,const std::string&,irods::callback)>( exec_rule_text ) );

    re->add_operation( "exec_rule_expression",
            std::function<irods::error(irods::default_re_ctx&,const std::string&,msParamArray_t*,irods::callback)>( exec_rule_expression ) );

    return re;
}
