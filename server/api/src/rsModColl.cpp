#include "irods/catalog_utilities.hpp"
#include "irods/client_connection.hpp"
#include "irods/icatHighLevelRoutines.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/irods_rs_comm_query.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/modColl.h"
#include "irods/rcMisc.h"
#include "irods/rsModColl.hpp"

namespace
{
    int _rsModColl(rsComm_t* rsComm, collInp_t* modCollInp)
    {
        std::string svc_role;
        irods::error ret = get_catalog_service_role(svc_role);
        if (!ret.ok()) {
            irods::log(PASS(ret));
            return ret.code();
        }

        if (irods::KW_CFG_SERVICE_ROLE_PROVIDER == svc_role) {
            int status;
            collInfo_t collInfo;
            char* tmpStr;

            int i;
            ruleExecInfo_t rei2;

            memset((char*) &rei2, 0, sizeof(ruleExecInfo_t));
            rei2.rsComm = rsComm;
            if (rsComm != NULL) {
                rei2.uoic = &rsComm->clientUser;
                rei2.uoip = &rsComm->proxyUser;
            }

            memset(&collInfo, 0, sizeof(collInfo));

            rstrcpy(collInfo.collName, modCollInp->collName, MAX_NAME_LEN);

            if ((tmpStr = getValByKey(&modCollInp->condInput, COLLECTION_TYPE_KW))) {
                rstrcpy(collInfo.collType, tmpStr, NAME_LEN);
            }

            if ((tmpStr = getValByKey(&modCollInp->condInput, COLLECTION_INFO1_KW))) {
                rstrcpy(collInfo.collInfo1, tmpStr, MAX_NAME_LEN);
            }

            if ((tmpStr = getValByKey(&modCollInp->condInput, COLLECTION_INFO2_KW))) {
                rstrcpy(collInfo.collInfo2, tmpStr, MAX_NAME_LEN);
            }

            if ((tmpStr = getValByKey(&modCollInp->condInput, COLLECTION_MTIME_KW))) {
                rstrcpy(collInfo.collModify, tmpStr, TIME_LEN);
            }

            /**  June 1 2009 for pre-post processing rule hooks **/
            rei2.coi = &collInfo;
            i = applyRule("acPreProcForModifyCollMeta", NULL, &rei2, NO_SAVE_REI);
            if (i < 0) {
                if (rei2.status < 0) {
                    i = rei2.status;
                }
                rodsLog(
                    LOG_ERROR,
                    "rsGeneralAdmin:acPreProcForModifyCollMeta error for %s,stat=%d",
                    modCollInp->collName,
                    i);
                return i;
            }
            /**  June 1 2009 for pre-post processing rule hooks **/

            status = chlModColl(rsComm, &collInfo);

            /**  June 1 2009 for pre-post processing rule hooks **/
            if (status >= 0) {
                i = applyRule("acPostProcForModifyCollMeta", NULL, &rei2, NO_SAVE_REI);
                if (i < 0) {
                    if (rei2.status < 0) {
                        i = rei2.status;
                    }
                    rodsLog(
                        LOG_ERROR,
                        "rsGeneralAdmin:acPostProcForModifyCollMeta error for %s,stat=%d",
                        modCollInp->collName,
                        i);
                    return i;
                }
            }
            /**  June 1 2009 for pre-post processing rule hooks **/

            /* XXXX need to commit */
            if (status >= 0) {
                status = chlCommit(rsComm);
            }
            else {
                chlRollback(rsComm);
            }

            return status;
        }
        else if (irods::KW_CFG_SERVICE_ROLE_CONSUMER == svc_role) {
            return SYS_NO_RCAT_SERVER_ERR;
        }
        else {
            rodsLog(LOG_ERROR, "role not supported [%s]", svc_role.c_str());
            return SYS_SERVICE_ROLE_NOT_SUPPORTED;
        }
    } // _rsModColl
} // anonymous namespace

int rsModColl(rsComm_t* rsComm, collInp_t* modCollInp)
{
    using log_api = irods::experimental::log::api;
    namespace ic = irods::experimental::catalog;

    try {
        const auto catalog_provider_host = ic::get_catalog_provider_host();

        if (LOCAL_HOST == catalog_provider_host.localFlag) {
            ic::throw_if_catalog_provider_service_role_is_invalid();
            return _rsModColl(rsComm, modCollInp);
        }

        // Some privileged clients may be affected by temporary elevated privileges. The redirect to the catalog service
        // provider here will cause the temporary privileged status granted to this connection to be lost in the
        // server-to-server connection. Many operations in iRODS use this API to update the collection mtime after a
        // data object modification or creation and requires privileged status to modify the collection in the event
        // that the user does not have permissions on the parent collection. A client connection is made here using the
        // service account rodsadmin credentials to modify the collection and then is immediately disconnected.
        if (irods::is_privileged_client(*rsComm)) {
            auto conn = irods::experimental::client_connection{
                catalog_provider_host.hostName->name,
                rsComm->myEnv.rodsPort,
                rsComm->myEnv.rodsUserName,
                rsComm->myEnv.rodsZone};

            RcComm& comm = static_cast<RcComm&>(conn);

            return rcModColl(&comm, modCollInp);
        }

        auto* host = ic::redirect_to_catalog_provider(*rsComm);
        return rcModColl(host->conn, modCollInp);
    }
    catch (const irods::exception& e) {
        log_api::error("[{}:{}] - caught iRODS exception [{}]", __func__, __LINE__, e.client_display_what());
        return e.code();
    }
    catch (const std::exception& e) {
        log_api::error("[{}:{}] - caught std::exception [{}]", __func__, __LINE__, e.what());
        return SYS_INTERNAL_ERR;
    }
    catch (...) {
        log_api::error("[{}:{}] - caught unknown error", __func__, __LINE__);
        return SYS_UNKNOWN_ERROR;
    }
} // rsModColl
