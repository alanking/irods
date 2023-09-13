#include "irods/rsGetLimitedPassword.hpp"

#include "irods/getLimitedPassword.h"
#include "irods/icatHighLevelRoutines.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/rcMisc.h" // for convert_time_str_to_epoch_seconds

int
rsGetLimitedPassword( rsComm_t *rsComm,
                      getLimitedPasswordInp_t *getLimitedPasswordInp,
                      getLimitedPasswordOut_t **getLimitedPasswordOut ) {
    rodsServerHost_t *rodsServerHost;
    int status;

    status = getAndConnRcatHost(rsComm, PRIMARY_RCAT, (const char*) NULL, &rodsServerHost);
    if ( status < 0 ) {
        return status;
    }

    if ( rodsServerHost->localFlag == LOCAL_HOST ) {
        std::string svc_role;
        irods::error ret = get_catalog_service_role(svc_role);
        if(!ret.ok()) {
            irods::log(PASS(ret));
            return ret.code();
        }
        if( irods::KW_CFG_SERVICE_ROLE_PROVIDER == svc_role ) {
            status = _rsGetLimitedPassword(
                         rsComm,
                         getLimitedPasswordInp,
                         getLimitedPasswordOut );
        } else if( irods::KW_CFG_SERVICE_ROLE_CONSUMER == svc_role ) {
            status = SYS_NO_RCAT_SERVER_ERR;
        } else {
            rodsLog(
                LOG_ERROR,
                "role not supported [%s]",
                svc_role.c_str() );
            status = SYS_SERVICE_ROLE_NOT_SUPPORTED;
        }
    }
    else {
        status = rcGetLimitedPassword( rodsServerHost->conn,
                                       getLimitedPasswordInp,
                                       getLimitedPasswordOut );
    }

    if ( status < 0 ) {
        rodsLog( LOG_NOTICE,
                 "rsGetLimitedPassword: rcGetLimitedPassword failed, status = %d",
                 status );
    }
    return status;
}

int
_rsGetLimitedPassword( rsComm_t *rsComm,
                       getLimitedPasswordInp_t *getLimitedPasswordInp,
                       getLimitedPasswordOut_t **getLimitedPasswordOut ) {
    // parse here to convert to seconds. This is a double-parse situation, but the interface is maintained.
    const auto ttl_str = fmt::format(
        "{}{}", getLimitedPasswordInp->ttl, getLimitedPasswordInp->unused1 ? getLimitedPasswordInp->unused1 : "h");

    const int ttl = convert_time_str_to_epoch_seconds(ttl_str.c_str());
    if (ttl < 0) {
        return ttl;
    }

    getLimitedPasswordOut_t* myGetLimitedPasswordOut;
    // NOLINTNEXTLINE(cppcoreguidelines-owning-memory, cppcoreguidelines-no-malloc)
    myGetLimitedPasswordOut = static_cast<getLimitedPasswordOut_t*>(std::malloc(sizeof(getLimitedPasswordOut_t)));

    const int status = chlMakeLimitedPw(rsComm, ttl, myGetLimitedPasswordOut->stringToHashWith);
    if (status < 0) {
        rodsLog(LOG_NOTICE, "_rsGetLimitedPassword: getLimitedPassword, status = %d", status);
    }

    *getLimitedPasswordOut = myGetLimitedPasswordOut;

    return status;
}
