#include "apiNumber.h"
#include "dataObjClose.h"
#include "dataObjCreate.h"
#include "dataObjGet.h"
#include "dataObjLock.h"
#include "dataObjOpen.h"
#include "dataObjOpr.hpp"
#include "dataObjPut.h"
#include "dataObjRepl.h"
#include "dataObjTrim.h"
#include "fileStageToCache.h"
#include "fileSyncToArch.h"
#include "getRemoteZoneResc.h"
#include "icatDefines.h"
#include "l3FileGetSingleBuf.h"
#include "l3FilePutSingleBuf.h"
#include "miscServerFunct.hpp"
#include "objMetaOpr.hpp"
#include "physPath.hpp"
#include "resource.hpp"
#include "rodsLog.h"
#include "rsDataCopy.hpp"
#include "rsDataObjClose.hpp"
#include "rsDataObjCreate.hpp"
#include "rsDataObjGet.hpp"
#include "rsDataObjOpen.hpp"
#include "rsDataObjPut.hpp"
#include "rsDataObjRead.hpp"
#include "rsDataObjRepl.hpp"
#include "rsDataObjUnlink.hpp"
#include "rsDataObjWrite.hpp"
#include "rsFileStageToCache.hpp"
#include "rsFileSyncToArch.hpp"
#include "rsL3FileGetSingleBuf.hpp"
#include "rsL3FilePutSingleBuf.hpp"
#include "rsUnbunAndRegPhyBunfile.hpp"
#include "rsUnregDataObj.hpp"
#include "specColl.hpp"
#include "unbunAndRegPhyBunfile.h"

#include "irods_at_scope_exit.hpp"
#include "irods_log.hpp"
#include "irods_logger.hpp"
#include "irods_random.hpp"
#include "irods_resource_backport.hpp"
#include "irods_resource_redirect.hpp"
#include "irods_server_api_call.hpp"
#include "irods_server_properties.hpp"
#include "irods_stacktrace.hpp"
#include "irods_string_tokenize.hpp"
#include "key_value_proxy.hpp"
#include "replica_access_table.hpp"
#include "replica_state_table.hpp"
#include "voting.hpp"

#include <string_view>
#include <vector>

#include <boost/lexical_cast.hpp>

#include "fmt/format.h"

namespace
{
    namespace ix = irods::experimental;
    using log = irods::experimental::log;

    auto make_source_replica_input(RsComm& _comm, const DataObjInp& _inp) -> DataObjInp
    {
        DataObjInp source_data_obj_inp = _inp;
        auto source_cond_input = irods::experimental::make_key_value_proxy(source_data_obj_inp.condInput);
        replKeyVal(&_inp.condInput, source_cond_input.get());

        source_cond_input.erase(DEST_RESC_HIER_STR_KW);
        source_cond_input.erase(DEST_RESC_NAME_KW);

        return source_data_obj_inp;
    } // make_source_replica_input

    auto resolve_source_replica_hierarchy(RsComm& _comm, DataObjInp& _inp) -> void
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

        if (cond_input.contains(RESC_HIER_STR_KW)) {
            irods::file_object_ptr obj{new irods::file_object()};
            if (const auto err = irods::file_object_factory(&_comm, &_inp, obj); !err.ok()) {
                THROW(err.code(), err.result());
            }
        }
        else {
            auto [obj, hier] = irods::resolve_resource_hierarchy(irods::OPEN_OPERATION, &_comm, _inp);
            cond_input[RESC_HIER_STR_KW] = hier;
        }
    } // resolve_source_replica_hierarchy

    auto make_destination_replica_input(RsComm& _comm, const DataObjInp& _inp) -> DataObjInp
    {
        DataObjInp destination_data_obj_inp = _inp;
        auto destination_cond_input = irods::experimental::make_key_value_proxy(destination_data_obj_inp.condInput);
        replKeyVal(&_inp.condInput, destination_cond_input.get());

        // Remove existing keywords used for source resource
        destination_cond_input.erase(RESC_NAME_KW);
        destination_cond_input.erase(RESC_HIER_STR_KW);

        // Get the destination resource that the client specified, or use the default resource
        if (!destination_cond_input.contains(DEST_RESC_HIER_STR_KW) &&
            !destination_cond_input.contains(DEST_RESC_NAME_KW)) {
            destination_cond_input[DEST_RESC_NAME_KW] = destination_cond_input.at(DEF_RESC_NAME_KW);
        }

        return destination_data_obj_inp;
    } // make_destination_replica_input

    auto resolve_destination_replica_hierarchy(RsComm& _comm, DataObjInp& _inp) -> irods::file_object_ptr
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

        std::string replica_number;
        if (cond_input.contains(REPL_NUM_KW)) {
            replica_number = cond_input[REPL_NUM_KW].value();

            // This keyword must be removed temporarily so that the voting mechanism does
            // not misinterpret it and change the operation from a CREATE to a WRITE.
            // See server/core/src/irods_resource_redirect.cpp for details.
            cond_input.erase(REPL_NUM_KW);
        }

        irods::at_scope_exit restore_replica_number_keyword{[&replica_number, &cond_input] {
            if (!replica_number.empty()) {
                cond_input[REPL_NUM_KW] = replica_number;
            }
        }};

        if (cond_input.contains(DEST_RESC_HIER_STR_KW)) {
            irods::file_object_ptr obj{new irods::file_object()};
            if (const auto err = irods::file_object_factory(&_comm, &_inp, obj); !err.ok()) {
                THROW(err.code(), err.result());
            }
            cond_input[RESC_HIER_STR_KW] = cond_input.at(DEST_RESC_HIER_STR_KW);
            return obj;
        }

        auto [obj, hier] = irods::resolve_resource_hierarchy(irods::CREATE_OPERATION, &_comm, _inp);
        cond_input[DEST_RESC_HIER_STR_KW] = hier;
        cond_input[RESC_HIER_STR_KW] = hier;

        irods::log(LOG_DEBUG, fmt::format(
            "[{}:{}] - path:[{}],hier:[{}]",
            __FUNCTION__, __LINE__, obj->logical_path(), hier));

        return obj;
    } // resolve_destination_replica_hierarchy

    int close_replica(RsComm& _comm, const int _fd, const int _status)
    {
        openedDataObjInp_t close_inp{};
        auto cond_input = irods::experimental::make_key_value_proxy(close_inp.condInput);
        //const irods::at_scope_exit free_cond_input{[&cond_input] { clearKeyVal(cond_input.get()); }};

        close_inp.l1descInx = _fd;
        L1desc[_fd].oprStatus = _status;

        const auto l1desc_cond_input = irods::experimental::make_key_value_proxy(L1desc[_fd].dataObjInp->condInput);
        if (l1desc_cond_input.contains(IN_PDMO_KW)) {
            cond_input[IN_PDMO_KW] = l1desc_cond_input.at(IN_PDMO_KW);
        }

        const int ec = rsDataObjClose(&_comm, &close_inp);
        if (ec < 0) {
            irods::log(LOG_ERROR, fmt::format("[{}] - rsDataObjClose failed with [{}]", __FUNCTION__, ec));
        }
        clearKeyVal(&close_inp.condInput);
        return ec;
    } // close_replica

    int open_source_replica(RsComm& _comm, DataObjInp& _source_data_obj_inp)
    {
        _source_data_obj_inp.oprType = REPLICATE_SRC;
        _source_data_obj_inp.openFlags = O_RDONLY;

        int fd = rsDataObjOpen(&_comm, &_source_data_obj_inp);
        if (fd < 0) {
            return fd;
        }

        const auto* info = L1desc[fd].dataObjInfo;

        irods::log(LOG_DEBUG, fmt::format(
            "[{}:{}] - opened source replica [{}] on [{}] (repl [{}])",
            __FUNCTION__, __LINE__, info->objPath, info->rescHier, info->replNum));

        // TODO: Consider using force flag and making this part of the voting process
        if (GOOD_REPLICA != L1desc[fd].dataObjInfo->replStatus) {
            const int status = SYS_NO_GOOD_REPLICA;
            close_replica(_comm, fd, status);
            return status;
        }

        return fd;
    } // open_source_replica

    int open_destination_replica(RsComm& _comm, DataObjInp& _destination_data_obj_inp, const int _source_l1desc_inx)
    {
        auto cond_input = ix::make_key_value_proxy(_destination_data_obj_inp.condInput);
        cond_input[REG_REPL_KW] = "";
        cond_input.erase(PURGE_CACHE_KW);

        _destination_data_obj_inp.oprType = REPLICATE_DEST;
        _destination_data_obj_inp.openFlags = O_CREAT | O_WRONLY | O_TRUNC;

        irods::log(LOG_DEBUG, fmt::format(
                "[{}:{}] - opening destination replica for [{}] (id:[{}]) on [{}]",
                __FUNCTION__, __LINE__,
                _destination_data_obj_inp.objPath,
                L1desc[_source_l1desc_inx].dataObjInfo->dataId,
                cond_input.at(RESC_HIER_STR_KW).value()));

        return rsDataObjOpen(&_comm, &_destination_data_obj_inp);
    } // open_destination_replica

    int replicate_data(RsComm& _comm, DataObjInp& _source_inp, DataObjInp& _destination_inp)
    {
        // Open source replica
        int source_fd = open_source_replica(_comm, _source_inp);
        if (source_fd < 3) {
            THROW(source_fd, "Failed opening source replica");
        }

        // Open destination replica
        int destination_fd = open_destination_replica(_comm, _destination_inp, source_fd);
        if (destination_fd < 3) {
            close_replica(_comm, source_fd, destination_fd);
            THROW(destination_fd, fmt::format(
                "[{}] - Failed opening destination replica for [{}]",
                __FUNCTION__, _source_inp.objPath));
        }
        L1desc[destination_fd].srcL1descInx = source_fd;

        // Copy data from source to destination
        int ret_ec = dataObjCopy(&_comm, destination_fd);
        if (ret_ec < 0) {
            rodsLog(LOG_ERROR, "[%s] - dataObjCopy failed for [%s]", __FUNCTION__, _destination_inp.objPath);
        }
        L1desc[destination_fd].bytesWritten = L1desc[destination_fd].dataObjInfo->dataSize;

        // Save the token for the replica access table so that it can be removed
        // in the event of a failure in close. On failure, the entry is restored,
        // but this will prevent retries of the operation as the token information
        // is lost by the time we have returned to the caller.
        const auto token = L1desc[destination_fd].replica_token;

        // Duplicate the source replica information so that it can be used while
        // finalizing the destination replica, which allows us to close the source replica
        // before the destination replica. This prevents a situation in which a replication
        // resulting from a replication (fileModified) can cause newly created source
        // replicas to be set to the intermediate state. We intentionally release the memory
        // so the free'ing of the L1 descriptor takes care of the memory cleanup.
        auto [source_replica, source_replica_lm] = irods::experimental::replica::duplicate_replica(*L1desc[source_fd].dataObjInfo);
        L1desc[destination_fd].replDataObjInfo = source_replica_lm.release();

        // Close source replica
        if (int close_status = close_replica(_comm, source_fd, 0); close_status < 0) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}] - closing source replica [{}] failed with [{}]",
                __FUNCTION__, _source_inp.objPath, close_status));

            if (ret_ec >= 0) {
                ret_ec = close_status;
            }
        }

        // Close destination replica
        if (int close_status = close_replica(_comm, destination_fd, ret_ec); close_status < 0) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}] - closing destination replica [{}] failed with [{}]",
                __FUNCTION__, _destination_inp.objPath, close_status));

            if (ret_ec >= 0) {
                ret_ec = close_status;
            }

            auto& rat = irods::experimental::replica_access_table::instance();
            rat.erase_pid(token, getpid());
        }

        return ret_ec;
    } // replicate_data

    int repl_data_obj(RsComm& _comm, const DataObjInp& _inp)
    {
        namespace irv = irods::experimental::resource::voting;

        dataObjInp_t source_inp = make_source_replica_input(_comm, _inp);
        dataObjInp_t destination_inp = make_destination_replica_input(_comm, _inp);
        const irods::at_scope_exit free_cond_inputs{[&destination_inp, &source_inp]() {
            clearKeyVal(&source_inp.condInput);
            clearKeyVal(&destination_inp.condInput);
        }};

        resolve_source_replica_hierarchy(_comm, source_inp);
        auto file_obj = resolve_destination_replica_hierarchy(_comm, destination_inp);

        if (file_obj->replicas().size() < 1) {
            THROW(SYS_REPLICA_DOES_NOT_EXIST, fmt::format("[{}] - no replica found for [{}]", __FUNCTION__, file_obj->logical_path()));
        }

        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);
        //auto source_cond_input = irods::experimental::make_key_value_proxy(source_inp.condInput);
        auto destination_cond_input = irods::experimental::make_key_value_proxy(destination_inp.condInput);

        if (cond_input.contains(ALL_KW)) {
            int last_status = 0;
            for (const auto& r : file_obj->replicas()) {
                irods::log(LOG_DEBUG, fmt::format(
                    "[{}:{}] - hier:[{}],status:[{}],vote:[{}]",
                    __FUNCTION__, __LINE__,
                    r.resc_hier(),
                    r.replica_status(),
                    r.vote()));

                if (GOOD_REPLICA == r.replica_status() && r.vote() > irv::vote::zero) {
                    destination_cond_input[RESC_HIER_STR_KW] = r.resc_hier();
                    last_status = replicate_data(_comm, source_inp, destination_inp);
                }
            }
            return last_status;
        }

        std::string_view destination_hierarchy = destination_cond_input.at(RESC_HIER_STR_KW).value();
        for (const auto& r : file_obj->replicas()) {
            // TODO: #4010 - This short-circuits resource logic for handling good replicas
            if (r.resc_hier() == destination_hierarchy) {
                if (GOOD_REPLICA == r.replica_status()) {
                    std::string_view source_hierarchy = getValByKey(&source_inp.condInput, RESC_HIER_STR_KW);

                    irods::log(LOG_DEBUG, fmt::format(
                        "[{}:{}] - hierarchy contains good replica already, source:[{}],dest:[{}]",
                        __FUNCTION__, __LINE__, destination_hierarchy, source_hierarchy));
                    return 0;
                }
                break;
            }
        }
        return replicate_data(_comm, source_inp, destination_inp);
    } // repl_data_obj

int singleL1Copy(
    rsComm_t *rsComm,
    dataCopyInp_t& dataCopyInp) {

    int trans_buff_size;
    try {
        trans_buff_size = irods::get_advanced_setting<const int>(irods::CFG_TRANS_BUFFER_SIZE_FOR_PARA_TRANS) * 1024 * 1024;
    } catch ( const irods::exception& e ) {
        irods::log(e);
        return e.code();
    }

    dataOprInp_t* dataOprInp = &dataCopyInp.dataOprInp;
    int destL1descInx = dataCopyInp.portalOprOut.l1descInx;
    int srcL1descInx = L1desc[destL1descInx].srcL1descInx;

    openedDataObjInp_t dataObjReadInp{};
    dataObjReadInp.l1descInx = srcL1descInx;
    dataObjReadInp.len = trans_buff_size;

    bytesBuf_t dataObjReadInpBBuf{};
    dataObjReadInpBBuf.buf = malloc(dataObjReadInp.len);
    dataObjReadInpBBuf.len = dataObjReadInp.len;
    const irods::at_scope_exit free_data_obj_read_inp_bbuf{[&dataObjReadInpBBuf]() {
        free(dataObjReadInpBBuf.buf);
    }};

    openedDataObjInp_t dataObjWriteInp{};
    dataObjWriteInp.l1descInx = destL1descInx;

    bytesBuf_t dataObjWriteInpBBuf{};
    dataObjWriteInpBBuf.buf = dataObjReadInpBBuf.buf;
    dataObjWriteInpBBuf.len = 0;

    int bytesRead{};
    rodsLong_t totalWritten = 0;
    while ((bytesRead = rsDataObjRead(rsComm, &dataObjReadInp, &dataObjReadInpBBuf)) > 0) {
        dataObjWriteInp.len = bytesRead;
        dataObjWriteInpBBuf.len = bytesRead;
        int bytesWritten = rsDataObjWrite(rsComm, &dataObjWriteInp, &dataObjWriteInpBBuf);
        if (bytesWritten != bytesRead) {
            rodsLog(LOG_ERROR,
                    "%s: Read %d bytes, Wrote %d bytes.\n ",
                    __FUNCTION__, bytesRead, bytesWritten );
            return SYS_COPY_LEN_ERR;
        }
        totalWritten += bytesWritten;
    }

    if (dataOprInp->dataSize > 0 &&
        !getValByKey(&dataOprInp->condInput, NO_CHK_COPY_LEN_KW) &&
        totalWritten != dataOprInp->dataSize) {
        rodsLog(LOG_ERROR,
                "%s: totalWritten %lld dataSize %lld mismatch",
                __FUNCTION__, totalWritten, dataOprInp->dataSize);
        return SYS_COPY_LEN_ERR;
    }
    return 0;
} // singleL1Copy

} // anonymous namespace

int rsDataObjRepl(
    rsComm_t *rsComm,
    dataObjInp_t *dataObjInp,
    transferStat_t **transStat) {
    if (!dataObjInp) {
        return SYS_INTERNAL_NULL_INPUT_ERR;
    }

    // -S and -n are not compatible
    if (getValByKey(&dataObjInp->condInput, RESC_NAME_KW) &&
        getValByKey(&dataObjInp->condInput, REPL_NUM_KW)) {
        return USER_INCOMPATIBLE_PARAMS;
    }

    // -a and -R are not compatible
    if (getValByKey(&dataObjInp->condInput, ALL_KW) &&
        getValByKey(&dataObjInp->condInput, DEST_RESC_NAME_KW)) {
        return USER_INCOMPATIBLE_PARAMS;
    }

    // Must be a privileged user to invoke SU
    if (getValByKey(&dataObjInp->condInput, SU_CLIENT_USER_KW) &&
        rsComm->proxyUser.authInfo.authFlag < REMOTE_PRIV_USER_AUTH) {
        return CAT_INSUFFICIENT_PRIVILEGE_LEVEL;
    }

    // Resolve path in linked collection if applicable
    dataObjInfo_t *dataObjInfo{};
    const irods::at_scope_exit free_data_obj_info{[dataObjInfo]() {
        freeAllDataObjInfo(dataObjInfo);
    }};
    int status = resolvePathInSpecColl( rsComm, dataObjInp->objPath,
                                    READ_COLL_PERM, 0, &dataObjInfo );
    if (status == DATA_OBJ_T && dataObjInfo && dataObjInfo->specColl) {
        if (dataObjInfo->specColl->collClass != LINKED_COLL) {
            return SYS_REG_OBJ_IN_SPEC_COLL;
        }
        rstrcpy(dataObjInp->objPath, dataObjInfo->objPath, MAX_NAME_LEN);
    }

    rodsServerHost_t *rodsServerHost{};
    const int remoteFlag = getAndConnRemoteZone(rsComm, dataObjInp, &rodsServerHost, REMOTE_OPEN);
    if ( remoteFlag < 0 ) {
        return remoteFlag;
    }
    else if (remoteFlag == REMOTE_HOST) {
        *transStat = (transferStat_t*)malloc(sizeof(transferStat_t));
        memset(*transStat, 0, sizeof(transferStat_t));
        status = _rcDataObjRepl(rodsServerHost->conn, dataObjInp, transStat);
        return status;
    }

    try {
        addKeyVal(&dataObjInp->condInput, IN_REPL_KW, "");
        const irods::at_scope_exit remove_in_repl{[&dataObjInp] { rmKeyVal(&dataObjInp->condInput, IN_REPL_KW); }};
        status = repl_data_obj(*rsComm, *dataObjInp);
    }
    catch (const irods::exception& e) {
        irods::log(e);
        status = e.code();
    }
    catch (const std::exception& e) {
        irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.what()));
        return SYS_INTERNAL_ERR;
    }
    catch (...) {
        irods::log(LOG_ERROR, fmt::format("[{}:{}] - unknown error occurred", __FUNCTION__, __LINE__));
        return SYS_UNKNOWN_ERROR;
    }

    if (status < 0 && status != DIRECT_ARCHIVE_ACCESS) {
        rodsLog(LOG_NOTICE, "%s - Failed to replicate data object. status:[%d]",
                __FUNCTION__, status);
    }
    return (status == DIRECT_ARCHIVE_ACCESS) ? 0 : status;
} // rsDataObjRepl

int dataObjCopy(
    rsComm_t* rsComm,
    int _destination_l1descInx) {

    int srcRemoteFlag{};
    int source_l1descInx = L1desc[_destination_l1descInx].srcL1descInx;
    int srcL3descInx = L1desc[source_l1descInx].l3descInx;
    if (L1desc[source_l1descInx].remoteZoneHost) {
        srcRemoteFlag = REMOTE_ZONE_HOST;
    }
    else {
        srcRemoteFlag = FileDesc[srcL3descInx].rodsServerHost->localFlag;
    }
    int destRemoteFlag{};
    int destL3descInx = L1desc[_destination_l1descInx].l3descInx;
    if (L1desc[_destination_l1descInx].remoteZoneHost) {
        destRemoteFlag = REMOTE_ZONE_HOST;
    }
    else {
        destRemoteFlag = FileDesc[destL3descInx].rodsServerHost->localFlag;
    }

    dataCopyInp_t dataCopyInp{};
    const irods::at_scope_exit clear_cond_input{[&dataCopyInp]() {
        clearKeyVal(&dataCopyInp.dataOprInp.condInput);
    }};

    portalOprOut_t* portalOprOut{};
    if (srcRemoteFlag == REMOTE_ZONE_HOST &&
        destRemoteFlag == REMOTE_ZONE_HOST) {
        // Destination: remote zone
        // Source: remote zone
        initDataOprInp(&dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_REM_OPR);
        L1desc[_destination_l1descInx].dataObjInp->numThreads = 0;
        dataCopyInp.portalOprOut.l1descInx = _destination_l1descInx;
        return singleL1Copy(rsComm, dataCopyInp);
    }

    if (srcRemoteFlag != REMOTE_ZONE_HOST &&
        destRemoteFlag != REMOTE_ZONE_HOST &&
        FileDesc[srcL3descInx].rodsServerHost == FileDesc[destL3descInx].rodsServerHost) {
        // Destination: local zone
        // Source: local zone
        // Source and destination host are the same
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, SAME_HOST_COPY_OPR );
        dataCopyInp.portalOprOut.numThreads = dataCopyInp.dataOprInp.numThreads;
        if ( srcRemoteFlag == LOCAL_HOST ) {
            addKeyVal(&dataCopyInp.dataOprInp.condInput, EXEC_LOCALLY_KW, "");
        }
    }
    else if (destRemoteFlag == REMOTE_ZONE_HOST ||
             (srcRemoteFlag == LOCAL_HOST && destRemoteFlag != LOCAL_HOST)) {
        // Destination: remote zone OR different host in local zone
        // Source: local zone
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_REM_OPR );
        if ( L1desc[_destination_l1descInx].dataObjInp->numThreads > 0 ) {
            int status = preProcParaPut( rsComm, _destination_l1descInx, &portalOprOut );
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaPut error for %s",
                        __FUNCTION__,
                        L1desc[source_l1descInx].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = _destination_l1descInx;
        }
        if ( srcRemoteFlag == LOCAL_HOST ) {
            addKeyVal( &dataCopyInp.dataOprInp.condInput, EXEC_LOCALLY_KW, "" );
        }
    }
    else if (srcRemoteFlag == REMOTE_ZONE_HOST ||
             (srcRemoteFlag != LOCAL_HOST && destRemoteFlag == LOCAL_HOST)) {
        // Destination: local zone
        // Source: remote zone OR different host in local zone
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_LOCAL_OPR );
        if ( L1desc[_destination_l1descInx].dataObjInp->numThreads > 0 ) {
            int status = preProcParaGet( rsComm, source_l1descInx, &portalOprOut );
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaGet error for %s",
                        __FUNCTION__,
                        L1desc[source_l1descInx].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = source_l1descInx;
        }
        if ( destRemoteFlag == LOCAL_HOST ) {
            addKeyVal( &dataCopyInp.dataOprInp.condInput, EXEC_LOCALLY_KW, "" );
        }
    }
    else {
        /* remote to remote */
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_LOCAL_OPR );
        if (L1desc[_destination_l1descInx].dataObjInp->numThreads > 0) {
            int status = preProcParaGet(rsComm, source_l1descInx, &portalOprOut);
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaGet error for %s",
                        __FUNCTION__,
                        L1desc[source_l1descInx].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = source_l1descInx;
        }
    }

    if (getValByKey(&L1desc[_destination_l1descInx].dataObjInp->condInput, NO_CHK_COPY_LEN_KW)) {
        addKeyVal(&dataCopyInp.dataOprInp.condInput, NO_CHK_COPY_LEN_KW, "");
        if (L1desc[_destination_l1descInx].dataObjInp->numThreads > 1) {
            L1desc[_destination_l1descInx].dataObjInp->numThreads = 1;
            L1desc[source_l1descInx].dataObjInp->numThreads = 1;
            dataCopyInp.portalOprOut.numThreads = 1;
        }
    }
    int status = rsDataCopy(rsComm, &dataCopyInp);
    if (status >= 0 && portalOprOut && L1desc[_destination_l1descInx].dataObjInp) {
        /* update numThreads since it could be changed by remote server */
        L1desc[_destination_l1descInx].dataObjInp->numThreads = portalOprOut->numThreads;
    }
    free(portalOprOut);
    return status;
} // dataObjCopy

int unbunAndStageBunfileObj(rsComm_t* rsComm, const char* bunfileObjPath, char** outCacheRescName) {

    /* query the bundle dataObj */
    dataObjInp_t dataObjInp{};
    rstrcpy( dataObjInp.objPath, bunfileObjPath, MAX_NAME_LEN );

    dataObjInfo_t *bunfileObjInfoHead{};
    int status = getDataObjInfo( rsComm, &dataObjInp, &bunfileObjInfoHead, NULL, 1 );
    if ( status < 0 ) {
        rodsLog( LOG_ERROR,
                 "unbunAndStageBunfileObj: getDataObjInfo of bunfile %s failed.stat=%d",
                 dataObjInp.objPath, status );
        return status;
    }
    status = _unbunAndStageBunfileObj( rsComm, &bunfileObjInfoHead, &dataObjInp.condInput,
                                       outCacheRescName, 0 );

    freeAllDataObjInfo( bunfileObjInfoHead );

    return status;
} // unbunAndStageBunfileObj

int _unbunAndStageBunfileObj(
    rsComm_t* rsComm,
    dataObjInfo_t** bunfileObjInfoHead,
    keyValPair_t * condInput,
    char** outCacheRescName,
    const int rmBunCopyFlag) {

    dataObjInp_t dataObjInp{};
    bzero( &dataObjInp.condInput, sizeof( dataObjInp.condInput ) );
    rstrcpy( dataObjInp.objPath, ( *bunfileObjInfoHead )->objPath, MAX_NAME_LEN );
    int status = sortObjInfoForOpen( bunfileObjInfoHead, condInput, 0 );

    addKeyVal( &dataObjInp.condInput, RESC_HIER_STR_KW, ( *bunfileObjInfoHead )->rescHier );
    if ( status < 0 ) {
        return status;
    }

    if (outCacheRescName) {
        *outCacheRescName = ( *bunfileObjInfoHead )->rescName;
    }

    addKeyVal(&dataObjInp.condInput, BUN_FILE_PATH_KW, (*bunfileObjInfoHead)->filePath);
    if ( rmBunCopyFlag > 0 ) {
        addKeyVal( &dataObjInp.condInput, RM_BUN_COPY_KW, "" );
    }
    if (!std::string_view{(*bunfileObjInfoHead)->dataType}.empty()) {
        addKeyVal(&dataObjInp.condInput, DATA_TYPE_KW, (*bunfileObjInfoHead)->dataType);
    }
    status = _rsUnbunAndRegPhyBunfile(rsComm, &dataObjInp, (*bunfileObjInfoHead)->rescName);

    return status;
} // _unbunAndStageBunfileObj
