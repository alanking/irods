#include "apiNumber.h"
#include "dataObjClose.h"
#include "dataObjLock.h"
#include "dataObjOpr.hpp"
#include "dataObjRepl.h"
#include "dataObjTrim.h"
#include "dataObjUnlink.h"
#include "fileClose.h"
#include "fileStat.h"
#include "getRescQuota.h"
#include "key_value_proxy.hpp"
#include "miscServerFunct.hpp"
#include "modAVUMetadata.h"
#include "modDataObjMeta.h"
#include "objMetaOpr.hpp"
#include "physPath.hpp"
#include "rcGlobalExtern.h"
#include "regDataObj.h"
#include "regReplica.h"
#include "resource.hpp"
#include "rodsErrorTable.h"
#include "rodsLog.h"
#include "rsDataObjClose.hpp"
#include "rsDataObjTrim.hpp"
#include "rsDataObjUnlink.hpp"
#include "rsFileClose.hpp"
#include "rsFileStat.hpp"
#include "rsGetRescQuota.hpp"
#include "rsGlobalExtern.hpp"
#include "rsModDataObjMeta.hpp"
#include "rsRegDataObj.hpp"
#include "rsRegReplica.hpp"
#include "rsSubStructFileClose.hpp"
#include "rsSubStructFileStat.hpp"
#include "rs_data_object_finalize.hpp"
#include "ruleExecSubmit.h"
#include "subStructFileClose.h"
#include "subStructFileRead.h"
#include "subStructFileStat.h"

// =-=-=-=-=-=-=-
#include "irods_at_scope_exit.hpp"
#include "irods_exception.hpp"
#include "irods_file_object.hpp"
#include "irods_hierarchy_parser.hpp"
#include "irods_resource_backport.hpp"
#include "irods_serialization.hpp"
#include "irods_server_api_call.hpp"
#include "irods_server_properties.hpp"
#include "irods_stacktrace.hpp"
#include "key_value_proxy.hpp"
#include "logical_locking.hpp"
#include "replica_access_table.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include <memory>
#include <functional>

#include <boost/shared_ptr.hpp>

#include <sys/types.h>
#include <unistd.h>

namespace {

namespace ix = irods::experimental;

void apply_static_pep(
    rsComm_t* rsComm,
    const int l1descInx,
    const int close_status,
    const char* pep_name)
{
    ruleExecInfo_t rei;
    initReiWithDataObjInp( &rei, rsComm,
                           L1desc[l1descInx].dataObjInp );
    rei.doi = L1desc[l1descInx].dataObjInfo;
    rei.status = close_status;

    // make resource properties available as rule session variables
    irods::get_resc_properties_as_kvp(rei.doi->rescHier, rei.condInputData);

    rei.status = applyRule(pep_name, NULL, &rei, NO_SAVE_REI );

    /* doi might have changed */
    L1desc[l1descInx].dataObjInfo = rei.doi;
    clearKeyVal(rei.condInputData);
    free(rei.condInputData);
} // apply_static_pep

void apply_static_peps(
    rsComm_t* rsComm,
    openedDataObjInp_t *dataObjCloseInp,
    const int l1descInx,
    const int close_status)
{
    /* note : this may overlap with acPostProcForPut or
     * acPostProcForCopy */
    if ( L1desc[l1descInx].openType == CREATE_TYPE ) {
        apply_static_pep(rsComm, l1descInx, close_status, "acPostProcForCreate");
    }
    else if ( L1desc[l1descInx].openType == OPEN_FOR_READ_TYPE ||
              L1desc[l1descInx].openType == OPEN_FOR_WRITE_TYPE ) {
        apply_static_pep(rsComm, l1descInx, close_status, "acPostProcForOpen");
    }
    else if ( L1desc[l1descInx].oprType == REPLICATE_DEST ) {
        apply_static_pep(rsComm, l1descInx, close_status, "acPostProcForRepl");
    }

    if ( L1desc[l1descInx].oprType == COPY_DEST ) {
        /* have to put copy first because the next test could
         * trigger put rule for copy operation */
        apply_static_pep(rsComm, l1descInx, close_status, "acPostProcForCopy");
    }
    else if ( L1desc[l1descInx].oprType == PUT_OPR ||
              L1desc[l1descInx].openType == CREATE_TYPE ||
              ( L1desc[l1descInx].openType == OPEN_FOR_WRITE_TYPE &&
                ( L1desc[l1descInx].bytesWritten > 0 ||
                  dataObjCloseInp->bytesWritten > 0 ) ) ) {
        apply_static_pep(rsComm, l1descInx, close_status, "acPostProcForPut");
    }
    else if ( L1desc[l1descInx].dataObjInp != NULL &&
              L1desc[l1descInx].dataObjInp->oprType == PHYMV_OPR ) {
        apply_static_pep(rsComm, l1descInx, close_status, "acPostProcForPhymv");
    }
} // apply_static_peps

auto trimDataObjInfo(
    rsComm_t&            _comm,
    const dataObjInfo_t& _info) -> int
{
    const auto replica = irods::experimental::replica::make_replica_proxy(_info);

    // =-=-=-=-=-=-=-
    // add the hier to a parser to get the leaf
    //std::string cache_resc = irods::hierarchy_parser{dataObjInfo->rescHier}.last_resc();

    dataObjInp_t dataObjInp{};
    rstrcpy( dataObjInp.objPath, replica.logical_path().data(), MAX_NAME_LEN );

    auto cond_input = irods::experimental::make_key_value_proxy(dataObjInp.condInput);
    cond_input[COPIES_KW] = "1";

    // =-=-=-=-=-=-=-
    // specify the cache repl num to trim just the cache
    cond_input[REPL_NUM_KW] = std::to_string(replica.replica_number());
    cond_input[RESC_HIER_STR_KW] = replica.hierarchy();

    ix::log::api::debug("[{}:{}] - trimming [{}] repl num:[{}],hier:[{}]",
        __FUNCTION__, __LINE__, replica.logical_path(), replica.replica_number(), replica.hierarchy());

    int status = rsDataObjTrim(&_comm, &dataObjInp );
    clearKeyVal( &dataObjInp.condInput );
    if ( status < 0 ) {
        rodsLogError( LOG_ERROR, status,
                      "%s: error trimming obj info for [%s]", __FUNCTION__, replica.logical_path().data());
    }
    return status;
} // trimDataObjInfo

auto purge_cache(rsComm_t& _comm, const int _l1descInx) -> int
{
    auto& l1desc = L1desc[_l1descInx];
    if (l1desc.purgeCacheFlag <= 0) {
        return 0;
    }

    ix::log::api::debug("[{}:{}] - purging cache file; info ptr:[{}]",
        __FUNCTION__, __LINE__, (void*)l1desc.dataObjInfo);

    const int trim_status = trimDataObjInfo(_comm, *l1desc.dataObjInfo);
    if (trim_status < 0) {
        rodsLogError(LOG_ERROR, trim_status,
                "%s: trimDataObjInfo error for %s",
                __FUNCTION__, l1desc.dataObjInfo->objPath);
    }
    return trim_status;
} // purge_cache

int _modDataObjSize(
    rsComm_t&      _comm,
    const int      _l1_desc_inx,
    dataObjInfo_t& _info)
{

    keyValPair_t regParam;
    modDataObjMeta_t modDataObjMetaInp;
    memset( &regParam, 0, sizeof( regParam ) );
    char tmpStr[MAX_NAME_LEN];
    snprintf( tmpStr, sizeof( tmpStr ), "%ji", ( intmax_t ) _info.dataSize );
    addKeyVal( &regParam, DATA_SIZE_KW, tmpStr );
    addKeyVal( &regParam, IN_PDMO_KW, _info.rescHier ); // to stop resource hierarchy recursion
    if ( getValByKey(
            &L1desc[_l1_desc_inx].dataObjInp->condInput,
            ADMIN_KW ) != NULL ) {
        addKeyVal( &regParam, ADMIN_KW, "" );
    }
    char* repl_status = getValByKey(&L1desc[_l1_desc_inx].dataObjInp->condInput, REPL_STATUS_KW);
    if (repl_status) {
        addKeyVal(&regParam, REPL_STATUS_KW, repl_status);
        L1desc[_l1_desc_inx].dataObjInfo->replStatus = std::stoi(repl_status);
    }

    if (getValByKey(&L1desc[_l1_desc_inx].dataObjInp->condInput, STALE_ALL_INTERMEDIATE_REPLICAS_KW)) {
        addKeyVal(&regParam, STALE_ALL_INTERMEDIATE_REPLICAS_KW, "");
    }

    modDataObjMetaInp.dataObjInfo = &_info;
    modDataObjMetaInp.regParam = &regParam;
    int status = rsModDataObjMeta(&_comm, &modDataObjMetaInp );
    if ( status < 0 ) {
        rodsLog( LOG_NOTICE,
                 "%s: rsModDataObjMeta failed, dataSize [%d] status = %d",
                 __FUNCTION__, _info.dataSize, status );
    }
    return status;
} // _modDataObjSize

auto procChksumForClose(rsComm_t& _comm, const int _l1_desc_inx) -> std::string_view
{
    namespace replica = irods::experimental::replica;

    int status = 0;
    auto l1desc = L1desc[_l1_desc_inx];
    auto target_replica = replica::make_replica_proxy(*l1desc.dataObjInfo);
    int oprType = l1desc.oprType;

    char* tmp_checksum_str{};

    const irods::at_scope_exit<std::function<void()>> free_temp_string{[tmp_checksum_str]
    {
        if (tmp_checksum_str) free(tmp_checksum_str);
    }};

    if ( oprType == REPLICATE_DEST || oprType == PHYMV_DEST ) {
        const int srcL1descInx = l1desc.srcL1descInx;
        if ( srcL1descInx <= 2 ) {
            THROW(SYS_FILE_DESC_OUT_OF_RANGE, fmt::format("srcL1descInx %d out of range", srcL1descInx));
        }

        const auto source_replica = replica::make_replica_proxy(*L1desc[srcL1descInx].dataObjInfo);
        if (!source_replica.checksum().empty()) {
            target_replica.cond_input()[ORIG_CHKSUM_KW] = source_replica.checksum();
        }

        if (!source_replica.checksum().empty() && source_replica.replica_status() > 0) {
            /* the source has chksum. Must verify chksum */
            status = _dataObjChksum(&_comm, target_replica.get(), &tmp_checksum_str);

            if ( status < 0 ) {
                target_replica.checksum("");
                if (DIRECT_ARCHIVE_ACCESS != status) {
                    THROW(status, fmt::format("_dataObjChksum error for %s, status = %d", target_replica.logical_path(), status));
                }

                target_replica.checksum(source_replica.checksum().data());
                return target_replica.checksum();
            }
            else if (!tmp_checksum_str) {
                THROW(SYS_INTERNAL_NULL_INPUT_ERR, "tmp_checksum_str is NULL");
            }

            target_replica.checksum(tmp_checksum_str);

            if (source_replica.checksum() != tmp_checksum_str) {
                THROW(USER_CHKSUM_MISMATCH, fmt::format(
                    "chksum mismatch for %s src [%s] new [%s]",
                    target_replica.logical_path(), source_replica.checksum(), tmp_checksum_str));
            }

            return target_replica.checksum();
        }
    }

    /* overwriting an old copy. need to verify the chksum again */
    if ( !target_replica.checksum().empty() && !l1desc.chksumFlag ) {
        l1desc.chksumFlag = VERIFY_CHKSUM;
    }

    if ( l1desc.chksumFlag == 0 ) {
        ix::log::api::info("[{}:{}] - no checksum flag", __FUNCTION__, __LINE__);
        return {};
    }
    else if ( l1desc.chksumFlag == VERIFY_CHKSUM ) {
        if ( strlen( l1desc.chksum ) > 0 ) {
            if ( strlen( l1desc.chksum ) > 0 ) {
                target_replica.cond_input()[ORIG_CHKSUM_KW] = l1desc.chksum;
            }

            status = _dataObjChksum(&_comm, target_replica.get(), &tmp_checksum_str );

            target_replica.cond_input().erase(ORIG_CHKSUM_KW);

            if ( status < 0 ) {
                THROW(status, "checksum operation failed");
            }

            if (!tmp_checksum_str) {
                THROW(SYS_INTERNAL_NULL_INPUT_ERR, "tmp_checksum_str is NULL");
            }

            /* from a put type operation */
            /* verify against the input value. */
            if (0 != strcmp(l1desc.chksum, tmp_checksum_str)) {
                THROW(USER_CHKSUM_MISMATCH, fmt::format(
                    "mismatch chksum for %s.inp=%s,compute %s",
                    target_replica.logical_path(), l1desc.chksum, tmp_checksum_str));
            }

            // checksum verified successfully; check if ORM should be updated
            if (target_replica.checksum() != tmp_checksum_str) {
                target_replica.checksum(tmp_checksum_str);
            }

            return target_replica.checksum();
        }
        else if ( oprType == REPLICATE_DEST ) {
            if (!target_replica.checksum().empty()) {
                target_replica.cond_input()[ORIG_CHKSUM_KW] = target_replica.checksum();
            }

            status = _dataObjChksum(&_comm, target_replica.get(), &tmp_checksum_str );

            target_replica.cond_input().erase(ORIG_CHKSUM_KW);

            if ( status < 0 ) {
                THROW(status, "checksum operation failed");
            }

            if (!tmp_checksum_str) {
                THROW(SYS_INTERNAL_NULL_INPUT_ERR, "tmp_checksum_str is NULL");
            }

            if (!target_replica.checksum().empty()) {
                if (target_replica.checksum() != tmp_checksum_str) {
                    THROW(USER_CHKSUM_MISMATCH, fmt::format(
                        "mismatch chksum for %s.Rcat=%s,comp %s",
                        target_replica.logical_path(), target_replica.checksum(), tmp_checksum_str));
                }
            }

            target_replica.checksum(tmp_checksum_str);
            return target_replica.checksum();
        }
        else if ( oprType == COPY_DEST ) {
            const int srcL1descInx = l1desc.srcL1descInx;
            if ( srcL1descInx <= 2 ) {
                rodsLog( LOG_DEBUG, "%s: invalid srcL1descInx %d for copy", __FUNCTION__, srcL1descInx );
                target_replica.checksum(tmp_checksum_str);
                return target_replica.checksum();
            }

            const auto source_replica = replica::make_replica_proxy(*L1desc[srcL1descInx].dataObjInfo);

            if (!source_replica.checksum().empty()) {
                target_replica.cond_input()[ORIG_CHKSUM_KW] = source_replica.checksum();
            }

            status = _dataObjChksum(&_comm, target_replica.get(), &tmp_checksum_str );

            target_replica.cond_input().erase(ORIG_CHKSUM_KW);

            if ( status < 0 ) {
                THROW(status, "checksum operation failed");
            }

            if (!tmp_checksum_str) {
                THROW(SYS_INTERNAL_NULL_INPUT_ERR, "tmp_checksum_str is NULL");
            }

            if (!source_replica.checksum().empty()) {
                if (source_replica.checksum() != tmp_checksum_str) {
                    THROW(USER_CHKSUM_MISMATCH, fmt::format(
                        "mismatch chksum for %s.Rcat=%s,comp %s",
                        target_replica.logical_path(), source_replica.checksum(), tmp_checksum_str));
                }
            }

            target_replica.checksum(tmp_checksum_str);
            return target_replica.checksum();
        }
    }
    else {	/* REG_CHKSUM */
        if ( strlen( l1desc.chksum ) > 0 ) {
            target_replica.cond_input()[ORIG_CHKSUM_KW] = l1desc.chksum;
        }

        status = _dataObjChksum(&_comm, target_replica.get(), &tmp_checksum_str );

        target_replica.cond_input().erase(ORIG_CHKSUM_KW);

        if ( status < 0 ) {
            THROW(status, "checksum operation failed");
        }

        target_replica.checksum(tmp_checksum_str);

        if ( strlen( l1desc.chksum ) > 0 ) {
            if (target_replica.checksum() == l1desc.chksum) {
                return {};
            }
        }
        else if ( oprType == COPY_DEST ) {
            /* created through copy */
            const int srcL1descInx = l1desc.srcL1descInx;
            if (srcL1descInx <= 2) {
                rodsLog( LOG_DEBUG, "%s: invalid srcL1descInx %d for copy", __FUNCTION__, srcL1descInx );
                return {};
            }

            if (const auto source_replica = replica::make_replica_proxy(*L1desc[srcL1descInx].dataObjInfo);
                source_replica.checksum().empty()) {
                return {};
            }
        }

        return target_replica.checksum();
    }

    return {};
} // procChksumForClose

int finalize_destination_replica_for_replication(
    rsComm_t& _comm,
    const openedDataObjInp_t& inp,
    const int l1descInx,
    ix::key_value_proxy<keyValPair_t>& regParam)
{
    const int srcL1descInx = L1desc[l1descInx].srcL1descInx;
    if (srcL1descInx <= 2) {
        THROW(SYS_FILE_DESC_OUT_OF_RANGE,
            fmt::format("{}: srcL1descInx {} out of range",
                __FUNCTION__, srcL1descInx));
    }


    dataObjInfo_t* srcDataObjInfo = L1desc[srcL1descInx].dataObjInfo;
    dataObjInfo_t *destDataObjInfo = L1desc[l1descInx].dataObjInfo;
    L1desc[l1descInx].dataObjInfo->replStatus = srcDataObjInfo->replStatus;
    regParam[REPL_STATUS_KW] = std::to_string(srcDataObjInfo->replStatus);
    regParam[DATA_SIZE_KW] = std::to_string(srcDataObjInfo->dataSize);
    regParam[DATA_MODIFY_KW] = std::to_string((int)time(nullptr));
    regParam[FILE_PATH_KW] = destDataObjInfo->filePath;

    const auto condInput = ix::make_key_value_proxy(L1desc[l1descInx].dataObjInp->condInput);
    if (condInput.contains(ADMIN_KW)) {
        regParam[ADMIN_KW] = condInput[ADMIN_KW];
    }
    if (const char* pdmo_kw = getValByKey(&inp.condInput, IN_PDMO_KW); pdmo_kw) {
        regParam[IN_PDMO_KW] = pdmo_kw;
    }
    if (condInput.contains(SYNC_OBJ_KW)) {
        regParam[SYNC_OBJ_KW] = condInput[SYNC_OBJ_KW];
    }
    if (PHYMV_DEST == L1desc[l1descInx].oprType) {
        regParam[REPL_NUM_KW] = std::to_string(srcDataObjInfo->replNum);
    }

    ix::log::api::trace("[{}:{}] - modifying [{}] on [{}]",
        __FUNCTION__, __LINE__, L1desc[l1descInx].dataObjInfo->objPath, L1desc[l1descInx].dataObjInfo->rescHier);

    modDataObjMeta_t modDataObjMetaInp{};
    modDataObjMetaInp.dataObjInfo = destDataObjInfo;
    modDataObjMetaInp.regParam = regParam.get();
    const int status = rsModDataObjMeta(&_comm, &modDataObjMetaInp);

    if (CREATE_TYPE == L1desc[l1descInx].openType) {
        /* update quota overrun */
        updatequotaOverrun( destDataObjInfo->rescHier, destDataObjInfo->dataSize, ALL_QUOTA );
    }

    if ( status < 0 ) {
        L1desc[l1descInx].oprStatus = status;
        /* don't delete replica with the same filePath */
        if (CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME != status) {
            l3Unlink(&_comm, L1desc[l1descInx].dataObjInfo );
        }
        rodsLog(LOG_NOTICE,
                "%s: RegReplica/ModDataObjMeta %s err. stat = %d",
                __FUNCTION__, destDataObjInfo->objPath, status );
    }

    return status;
} // finalize_destination_replica_for_replication

int finalize_destination_data_object_for_put_or_copy(
    rsComm_t& _comm,
    const openedDataObjInp_t& inp,
    const int l1descInx,
    const rodsLong_t size_in_vault,
    ix::key_value_proxy<keyValPair_t>& regParam)
{
    const auto condInput = ix::make_key_value_proxy(L1desc[l1descInx].dataObjInp->condInput);
    if (L1desc[l1descInx].l3descInx < 2 &&
        condInput.contains(CROSS_ZONE_CREATE_KW) &&
        INTERMEDIATE_REPLICA == L1desc[l1descInx].replStatus) {
        /* the comes from a cross zone copy. have not been registered yet */
        const int status = svrRegDataObj(&_comm, L1desc[l1descInx].dataObjInfo );
        if (status < 0) {
            L1desc[l1descInx].oprStatus = status;
            rodsLog(LOG_NOTICE,
                    "%s: svrRegDataObj for %s failed, status = %d",
                    __FUNCTION__, L1desc[l1descInx].dataObjInfo->objPath, status );
        }
    }

    if ( L1desc[l1descInx].dataObjInfo->dataSize != size_in_vault ) {
        /* update this in case we need to replicate it */
        regParam[DATA_SIZE_KW] = std::to_string(size_in_vault);
        L1desc[l1descInx].dataObjInfo->dataSize = size_in_vault;
    }

    // TODO: Here is where we need to update the replica statuses
    if (OPEN_FOR_WRITE_TYPE == L1desc[l1descInx].openType) {
        regParam[ALL_REPL_STATUS_KW] = "";
        regParam[DATA_MODIFY_KW] = std::to_string((int)time(nullptr));
    }
    else {
        L1desc[l1descInx].dataObjInfo->replStatus = GOOD_REPLICA;
        regParam[REPL_STATUS_KW] = std::to_string(L1desc[l1descInx].dataObjInfo->replStatus);
    }

    modDataObjMeta_t modDataObjMetaInp{};
    modDataObjMetaInp.dataObjInfo = L1desc[l1descInx].dataObjInfo;
    modDataObjMetaInp.regParam = regParam.get();
    const int status = rsModDataObjMeta(&_comm, &modDataObjMetaInp);
    if (status < 0) {
        THROW(status,
            fmt::format("{}: rsModDataObjMeta failed with {}",
            __FUNCTION__, status));
    }

    try {
        applyACLFromKVP(&_comm, L1desc[l1descInx].dataObjInp);
        applyMetadataFromKVP(&_comm, L1desc[l1descInx].dataObjInp);
    }
    catch (const irods::exception& e) {
        if ( L1desc[l1descInx].dataObjInp->oprType == PUT_OPR ) {
            rsDataObjUnlink( &_comm, L1desc[l1descInx].dataObjInp );
        }
        throw;
    }

    if (GOOD_REPLICA == L1desc[l1descInx].replStatus) {
        /* update quota overrun */
        updatequotaOverrun( L1desc[l1descInx].dataObjInfo->rescHier, size_in_vault, ALL_QUOTA );
    }

    return status;
} // finalize_destination_data_object_for_put_or_copy

int finalize_replica_after_failed_operation(
    rsComm_t& _comm,
    const int _l1descInx)
{
    auto& l1desc = L1desc[_l1descInx];

    ix::log::api::trace("[{}:{}] - path:[{}], hier:[{}]",
        __FUNCTION__, __LINE__, l1desc.dataObjInfo->objPath, l1desc.dataObjInfo->rescHier);

    // #3674 - elide any additional errors for catalog update if this is an intermediate replica
    // TODO: Why?
    if(l1desc.oprType == REPLICATE_OPR ||
       l1desc.oprType == REPLICATE_DEST ||
       l1desc.oprType == REPLICATE_SRC ) {
        // Make change here if we want to stop replication
        return l1desc.oprStatus;
    }

    const rodsLong_t vault_size = getSizeInVault(&_comm, l1desc.dataObjInfo);
    if (vault_size < 0) {
        rodsLog( LOG_ERROR,
                 "%s - getSizeInVault failed [%ld]",
                 __FUNCTION__, vault_size );
        return vault_size;
    }

    L1desc[_l1descInx].dataObjInfo->replStatus = STALE_REPLICA;

    auto p = ix::make_key_value_proxy(l1desc.dataObjInp->condInput);
    p[REPL_STATUS_KW] = std::to_string(L1desc[_l1descInx].dataObjInfo->replStatus);
    p[STALE_ALL_INTERMEDIATE_REPLICAS_KW] = "";
    l1desc.dataObjInfo->dataSize = vault_size;
    if (const int status = _modDataObjSize(_comm, _l1descInx, *l1desc.dataObjInfo); status < 0) {
        rodsLog( LOG_ERROR,
                 "%s - _modDataObjSize failed [%d]",
                 __FUNCTION__, status );
        return status;
    }

    /* an error has occurred */
    return L1desc[_l1descInx].oprStatus;
} // finalize_replica_after_failed_operation

int finalize_replica_with_no_bytes_written(
    rsComm_t& _comm,
    const int _l1descInx)
{
    l1desc_t& l1desc = L1desc[_l1descInx];

    ix::log::api::trace("[{}:{}] - path:[{}], hier:[{}]",
        __FUNCTION__, __LINE__, l1desc.dataObjInfo->objPath, l1desc.dataObjInfo->rescHier);

    try {
        applyMetadataFromKVP(&_comm, l1desc.dataObjInp);
        applyACLFromKVP(&_comm, l1desc.dataObjInp);
    }
    catch ( const irods::exception& e ) {
        rodsLog( LOG_ERROR, "%s", e.what() );
        if ( l1desc.dataObjInp->oprType == PUT_OPR ) {
            rsDataObjUnlink(&_comm, l1desc.dataObjInp );
        }
        return e.code();
    }

    if (PUT_OPR != l1desc.oprType || !l1desc.chksumFlag) {
        // return success as the rest is put-specific...
        return 0;
    }

    keyValPair_t regParam{};
    auto kvp = ix::make_key_value_proxy(regParam);
    kvp[OPEN_TYPE_KW] = std::to_string(l1desc.openType);

    if (const std::string_view checksum = procChksumForClose(_comm, _l1descInx); !checksum.empty()) {
        kvp[CHKSUM_KW] = checksum;
    }

    modDataObjMeta_t modDataObjMetaInp{};
    modDataObjMetaInp.dataObjInfo = l1desc.dataObjInfo;
    modDataObjMetaInp.regParam = &regParam;
    return rsModDataObjMeta(&_comm, &modDataObjMetaInp );
} // finalize_replica_with_no_bytes_written

bool bytes_written_in_operation(const l1desc_t& l1desc)
{
    return l1desc.bytesWritten >= 0 ||
           REPLICATE_DEST == l1desc.oprType ||
           PHYMV_DEST == l1desc.oprType ||
           COPY_DEST == l1desc.oprType;
} // bytes_written_in_operation

bool cross_zone_write_operation(
    const openedDataObjInp_t& inp,
    const l1desc_t& l1desc)
{
    return inp.bytesWritten > 0 && l1desc.bytesWritten <= 0;
} // cross_zone_write_operation

rodsLong_t get_size_in_vault(
    rsComm_t& _comm,
    const l1desc_t& l1desc)
{
    rodsLong_t size_in_vault = getSizeInVault(&_comm, l1desc.dataObjInfo);

    // since we are not filtering out writes to archive resources, the
    // archive plugins report UNKNOWN_FILE_SZ as their size since they may
    // not be able to stat the file.  filter that out and trust the plugin
    // in this instance
    if (UNKNOWN_FILE_SZ == size_in_vault && l1desc.dataSize >= 0) {
        return l1desc.dataSize;
    }

    if (size_in_vault < 0 && UNKNOWN_FILE_SZ != size_in_vault) {
        THROW((int)size_in_vault,
            fmt::format("{}: getSizeInVault error for {}, status = {}",
            __FUNCTION__, l1desc.dataObjInfo->objPath, size_in_vault));
    }

    // check for consistency of the write operation
    if (size_in_vault != l1desc.dataSize && l1desc.dataSize > 0 &&
        !getValByKey(&l1desc.dataObjInp->condInput, NO_CHK_COPY_LEN_KW)) {
        THROW(SYS_COPY_LEN_ERR,
            fmt::format("{}: size in vault {} != target size {}",
            __FUNCTION__, size_in_vault, l1desc.dataSize));
    }

    return size_in_vault;
} // get_size_in_vault

void close_physical_file(rsComm_t* comm, const int l1descInx)
{
    const int l3descInx = L1desc[l1descInx].l3descInx;
    if (l3descInx < 3) {
        // This message will appear a lot for single buffer gets -- it is not necessarily an error
        ix::log::api::debug("invalid l3 descriptor index [{}]", l3descInx);
        return;
    }

    if (const int status = l3Close(comm, l1descInx); status < 0) {
        THROW(status, fmt::format("l3Close of {} failed, status = {}", l3descInx, status));
    }
} // close_physical_file

auto update_checksum_if_needed(rsComm_t& _comm, const int _l1descInx) -> std::string_view
{
    l1desc_t& l1desc = L1desc[_l1descInx];

    bool update_checksum = !getValByKey(&l1desc.dataObjInp->condInput, NO_CHK_COPY_LEN_KW);
    if ((OPEN_FOR_WRITE_TYPE == l1desc.openType || CREATE_TYPE == l1desc.openType) &&
        !std::string_view{l1desc.dataObjInfo->chksum}.empty()) {
        l1desc.chksumFlag = REG_CHKSUM;
        update_checksum = true;
    }

    if (update_checksum) {
        if (const std::string_view checksum = procChksumForClose(_comm, _l1descInx); !checksum.empty()) {
            return checksum;
        }
    }

    return {};
} // update_checksum_if_needed

int finalize_replica(
    rsComm_t& _comm,
    const int _inx,
    const openedDataObjInp_t& _inp)
{
    try {
        auto& l1desc = L1desc[_inx];

        ix::log::api::debug("[{}:{}] - finalizing replica [{}] on [{}]",
            __FUNCTION__, __LINE__, l1desc.dataObjInfo->objPath, l1desc.dataObjInfo->rescHier);

        if (l1desc.oprStatus < 0) {
            return finalize_replica_after_failed_operation(_comm, _inx);
        }

        if (cross_zone_write_operation(_inp, l1desc)) {
            l1desc.bytesWritten = _inp.bytesWritten;
        }

        if (!bytes_written_in_operation(l1desc)) {
            purge_cache(_comm, _inx);
            return finalize_replica_with_no_bytes_written(_comm, _inx);
        }

        const auto size_in_vault = get_size_in_vault(_comm, l1desc);

        keyValPair_t regParam{};
        auto p = ix::make_key_value_proxy(regParam);

        p[CHKSUM_KW] = update_checksum_if_needed(_comm, _inx);

        int status{};
        if (REPLICATE_DEST == l1desc.oprType || PHYMV_DEST == l1desc.oprType) {
            status = finalize_destination_replica_for_replication(_comm, _inp, _inx, p);
        }
        else if (!l1desc.dataObjInfo->specColl) {
            status = finalize_destination_data_object_for_put_or_copy(_comm, _inp, _inx, size_in_vault, p);
        }

        l1desc.bytesWritten = size_in_vault;
        l1desc.dataObjInfo->dataSize = size_in_vault;

        purge_cache(_comm, _inx);

        return status;
    }
    catch (const irods::exception& e) {
        irods::log(e);
        return e.code();
    }
} // finalize_replica

void unlock_file_descriptor(
    rsComm_t* comm,
    const int l1descInx)
{
    char fd_string[NAME_LEN]{};
    snprintf(fd_string, sizeof( fd_string ), "%-d", L1desc[l1descInx].lockFd);
    addKeyVal(&L1desc[l1descInx].dataObjInp->condInput, LOCK_FD_KW, fd_string);
    irods::server_api_call(
        DATA_OBJ_UNLOCK_AN,
        comm,
        L1desc[l1descInx].dataObjInp,
        nullptr, (void**)nullptr, nullptr);
    L1desc[l1descInx].lockFd = -1;
} // unlock_file_descriptor

auto sync_status_with_catalog(rsComm_t& _comm, const l1desc_t& _l1desc) -> void
{
    namespace data_object = irods::experimental::data_object;

    const auto input = data_object::to_json(*_l1desc.dataObjInfo);

    ix::log::api::info("[{}:{}] - input:[{}]", __FUNCTION__, __LINE__, input.dump());

    char* output{};
    if (const auto ec = rs_data_object_finalize(&_comm, input.dump().c_str(), &output); ec) {
        ix::log::api::error("[{}] - updating data object failed with [{}]", __FUNCTION__, ec);
        THROW(ec, "failed to update data object");
    }
} // sync_status_with_catalog

} // anonymous namespace

int l3Close(
    rsComm_t *rsComm,
    int l1descInx)
{
    fileCloseInp_t fileCloseInp;
    int status = 0;
    dataObjInfo_t* dataObjInfo = L1desc[l1descInx].dataObjInfo;

    std::string location;
    irods::error ret = irods::get_loc_for_hier_string( dataObjInfo->rescHier, location );
    if (!ret.ok()) {
        irods::log( PASSMSG( "l3Close - failed in get_loc_for_hier_string", ret ) );
        return ret.code();
    }

    if ( getStructFileType( dataObjInfo->specColl ) >= 0 ) {
        subStructFileFdOprInp_t subStructFileCloseInp;
        memset( &subStructFileCloseInp, 0, sizeof( subStructFileCloseInp ) );
        subStructFileCloseInp.type = dataObjInfo->specColl->type;
        subStructFileCloseInp.fd = L1desc[l1descInx].l3descInx;
        rstrcpy( subStructFileCloseInp.addr.hostAddr, location.c_str(), NAME_LEN );
        rstrcpy( subStructFileCloseInp.resc_hier, dataObjInfo->rescHier, MAX_NAME_LEN );
        status = rsSubStructFileClose( rsComm, &subStructFileCloseInp );
    }
    else {
        memset( &fileCloseInp, 0, sizeof( fileCloseInp ) );
        fileCloseInp.fileInx = L1desc[l1descInx].l3descInx;
        rstrcpy( fileCloseInp.in_pdmo, L1desc[l1descInx].in_pdmo, MAX_NAME_LEN );
        status = rsFileClose( rsComm, &fileCloseInp );

    }
    return status;
} // l3Close

int rsDataObjClose(
    rsComm_t *rsComm,
    openedDataObjInp_t *dataObjCloseInp)
{
    const auto l1descInx = dataObjCloseInp->l1descInx; 
    if (l1descInx < 3 || l1descInx >= NUM_L1_DESC) {
        rodsLog(LOG_NOTICE,
            "rsDataObjClose: l1descInx %d out of range", l1descInx);
        return SYS_FILE_DESC_OUT_OF_RANGE;
    }

    const auto& l1desc = L1desc[dataObjCloseInp->l1descInx];
    std::unique_ptr<irods::at_scope_exit<std::function<void()>>> restore_entry;

    int ec = 0;

    // Replica access tokens only apply to write operations.
    if ((l1desc.dataObjInp->openFlags & O_ACCMODE) != O_RDONLY) {
        if (!l1desc.replica_token.empty()) {
            // Capture the replica token and erase the PID from the replica access table.
            // This must always happen before calling "irsDataObjClose" because other operations
            // may attempt to open this replica, but will fail because those operations do not
            // have the replica token.
            if (auto entry = ix::replica_access_table::instance().erase_pid(l1desc.replica_token, getpid()); entry) {
                // "entry" should always be populated in normal situations.
                // Because closing a data object triggers a file modified notification, it is
                // important to be able to restore the previously removed replica access table entry.
                // This is required so that the iRODS state is maintained in relation to the client.
                restore_entry.reset(new irods::at_scope_exit<std::function<void()>>{
                    [&ec, e = std::move(*entry)] {
                        if (ec != 0) {
                            ix::replica_access_table::instance().restore(e);
                        }
                    }
                });
            }
        }
        else {
            ix::log::api::warn("No replica access token in L1 descriptor. Ignoring replica access table. "
                               "[path={}, resource_hierarchy={}]",
                               l1desc.dataObjInfo->objPath, l1desc.dataObjInfo->rescHier);
        }
    }

    // ensure that l1 descriptor is in use before closing
    if (l1desc.inuseFlag != FD_INUSE) {
        rodsLog(LOG_ERROR,
            "rsDataObjClose: l1descInx %d out of range", l1descInx);
        // Capture the error code so that the at_scope_exit handler can respond to it.
        return ec = BAD_INPUT_DESC_INDEX;
    }

    // sanity check for in-flight l1 descriptor
    if(!l1desc.dataObjInp) {
        rodsLog(LOG_ERROR,
            "rsDataObjClose: invalid dataObjInp for index %d", l1descInx);
        // Capture the error code so that the at_scope_exit handler can respond to it.
        return ec = SYS_INVALID_INPUT_PARAM;
    }

    if (l1desc.remoteZoneHost) {
        dataObjCloseInp->l1descInx = l1desc.remoteL1descInx;
        ec = rcDataObjClose( l1desc.remoteZoneHost->conn, dataObjCloseInp );
        dataObjCloseInp->l1descInx = l1descInx;
        freeL1desc( l1descInx );
        return ec;
    }

    try {
        namespace data_object = irods::experimental::data_object;

        const int l1descInx = dataObjCloseInp->l1descInx;

        // TODO: is this being closed?
        close_physical_file(rsComm, l1descInx);

        ec = finalize_replica(*rsComm, l1descInx, *dataObjCloseInp);

        if (l1desc.lockFd > 0) {
            unlock_file_descriptor(rsComm, l1descInx);
        }

        // TODO: Need to extract original replica states, somehow, and restore them here
        sync_status_with_catalog(*rsComm, L1desc[l1descInx]);

        if (ec < 0 || l1desc.oprStatus < 0) {
            freeL1desc(l1descInx);
            return ec;
        }

        apply_static_peps(rsComm, dataObjCloseInp, l1descInx, ec);
    }
    catch (const irods::exception& e) {
        irods::log(e);
        // Capture the error code so that the at_scope_exit handler can respond to it.
        return ec = e.code();
    }

    freeL1desc(l1descInx);
    return ec;
} // rsDataObjClose

