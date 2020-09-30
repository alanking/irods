#include "dataObjRepl.h"
#include "dataObjOpr.hpp"
#include "dataObjCreate.h"
#include "dataObjOpen.h"
#include "dataObjClose.h"
#include "dataObjPut.h"
#include "dataObjGet.h"
#include "rodsLog.h"
#include "objMetaOpr.hpp"
#include "physPath.hpp"
#include "specColl.hpp"
#include "resource.hpp"
#include "icatDefines.h"
#include "getRemoteZoneResc.h"
#include "l3FileGetSingleBuf.h"
#include "fileSyncToArch.h"
#include "fileStageToCache.h"
#include "unbunAndRegPhyBunfile.h"
#include "dataObjTrim.h"
#include "dataObjLock.h"
#include "miscServerFunct.hpp"
#include "rsDataObjRepl.hpp"
#include "apiNumber.h"
#include "rsDataCopy.hpp"
#include "rsDataObjCreate.hpp"
#include "rsDataObjOpen.hpp"
#include "rsDataObjRead.hpp"
#include "rsDataObjWrite.hpp"
#include "rsDataObjClose.hpp"
#include "rsDataObjUnlink.hpp"
#include "rsUnregDataObj.hpp"
#include "rsL3FileGetSingleBuf.hpp"
#include "rsDataObjGet.hpp"
#include "rsDataObjPut.hpp"
#include "rsL3FilePutSingleBuf.hpp"
#include "rsUnbunAndRegPhyBunfile.hpp"

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
#include "resolve_resource_hierarchy.hpp"
#include "voting.hpp"

#include <string_view>
#include <vector>

namespace
{
    namespace ir = irods::experimental::resource;
    namespace irv = irods::experimental::resource::voting;
    using data_object_proxy = irods::experimental::data_object::data_object_proxy<dataObjInfo_t>;

    auto init_source_replica_input(const dataObjInp_t& _inp) -> dataObjInp_t
    {
        dataObjInp_t source_data_obj_inp = _inp;
        replKeyVal(&_inp.condInput, &source_data_obj_inp.condInput);

        // Remove existing keywords used for destination resource
        auto cond_input = irods::experimental::make_key_value_proxy(source_data_obj_inp.condInput);
        cond_input.erase(DEST_RESC_NAME_KW);
        cond_input.erase(DEST_RESC_HIER_STR_KW);

        return source_data_obj_inp;
    } // init_source_replica_input

    auto init_destination_replica_input(const dataObjInp_t& _inp) -> dataObjInp_t
    {
        dataObjInp_t destination_data_obj_inp = _inp;
        replKeyVal(&_inp.condInput, &destination_data_obj_inp.condInput);

        // Remove existing keywords used for source resource
        auto cond_input = irods::experimental::make_key_value_proxy(destination_data_obj_inp.condInput);
        cond_input.erase(RESC_NAME_KW);
        cond_input.erase(RESC_HIER_STR_KW);

        if (cond_input.contains(DEST_RESC_HIER_STR_KW)) {
            // Other operations only look for RESC_HIER_STR_KW, so set the value here
            cond_input[RESC_HIER_STR_KW] = cond_input.at(DEST_RESC_HIER_STR_KW);
        }
        else if (!cond_input.contains(DEST_RESC_NAME_KW)) {
            // Use default resource if the client did not specify a destination
            cond_input[DEST_RESC_NAME_KW] = cond_input.at(DEF_RESC_NAME_KW);
        }

        cond_input[REG_REPL_KW] = "";

        return destination_data_obj_inp;
    } // init_destination_replica_input

    auto resolve_hierarchy_for_source(RsComm& _comm, dataObjInp_t& _source_inp, data_object_proxy& _obj)
    {
        auto source_cond_input = irods::experimental::make_key_value_proxy(_source_inp.condInput);

        if (!source_cond_input.contains(RESC_HIER_STR_KW)) {
            irods::log(LOG_NOTICE, fmt::format(
                "[{}:{}] - resolving hierarchy for [{}] as source, repl num:[{}]",
                __FUNCTION__, __LINE__, _obj.logical_path(), _obj.requested_replica()));

            const auto winner = ir::resolve_resource_hierarchy(_comm, irods::OPEN_OPERATION, _source_inp, _obj);

            source_cond_input[RESC_HIER_STR_KW] = std::get<std::string>(winner);
        }

        const auto& winner = std::get<std::string>(_obj.winner());
        const bool winner_is_stale = [&]
        {
            for (const auto& r : _obj.replicas()) {
                if (r.hierarchy() == winner && STALE_REPLICA == r.replica_status()) {
                    return true;
                }
            }
            return false;
        }();

        if (winner_is_stale) {
            THROW(SYS_NO_GOOD_REPLICA, fmt::format(
                "the selected replica for [{}] on [{}] is stale",
                _obj.logical_path(), winner));
        }

        irods::log(LOG_NOTICE, fmt::format(
            "[{}:{}] - resolved source [{}]",
            __FUNCTION__, __LINE__, source_cond_input.at(RESC_HIER_STR_KW).value()));
    } // resolve_hierarchy_for_source

    auto resolve_hierarchy_for_destination(RsComm& _comm, dataObjInp_t& _destination_inp, data_object_proxy& _obj)
    {
        auto destination_cond_input = irods::experimental::make_key_value_proxy(_destination_inp.condInput);

        if (!destination_cond_input.contains(DEST_RESC_HIER_STR_KW)) {
            std::string replica_number;

            if (destination_cond_input.contains(REPL_NUM_KW)) {
                replica_number = destination_cond_input.at(REPL_NUM_KW).value();

                // This keyword must be removed temporarily so that the voting mechanism does
                // not misinterpret it and change the operation from a CREATE to a WRITE.
                // See server/core/src/irods_resource_redirect.cpp for details.
                destination_cond_input.erase(REPL_NUM_KW);
            }

            irods::at_scope_exit restore_replica_number_keyword{[&replica_number, &destination_cond_input] {
                if (!replica_number.empty()) {
                    destination_cond_input[REPL_NUM_KW] = replica_number;
                }
            }};

            irods::log(LOG_NOTICE, fmt::format(
                "[{}:{}] - resolving hierarchy for [{}] as destination",
                __FUNCTION__, __LINE__, _obj.logical_path()));

            const auto winner = ir::resolve_resource_hierarchy(_comm, irods::CREATE_OPERATION, _destination_inp, _obj);

            destination_cond_input[DEST_RESC_HIER_STR_KW] = std::get<std::string>(winner);
        }
        destination_cond_input[RESC_HIER_STR_KW] = destination_cond_input.at(DEST_RESC_HIER_STR_KW);

        irods::log(LOG_NOTICE, fmt::format(
            "[{}:{}] - resolved destination [{}]",
            __FUNCTION__, __LINE__, destination_cond_input.at(RESC_HIER_STR_KW).value()));
    } // resolve_hierarchy_for_destination

    int open_source_replica(RsComm& _comm, dataObjInp_t& _source_inp)
    {
        _source_inp.oprType = REPLICATE_SRC;
        _source_inp.openFlags = O_RDONLY;

        return rsDataObjOpen(&_comm, &_source_inp);
    } // open_source_replica

    int open_destination_replica(RsComm& _comm, dataObjInp_t& _destination_inp)
    {
        irods::experimental::key_value_proxy{_destination_inp.condInput}.erase(PURGE_CACHE_KW);

        _destination_inp.oprType = REPLICATE_DEST;
        _destination_inp.openFlags = O_CREAT | O_WRONLY | O_TRUNC;

        return rsDataObjOpen(&_comm, &_destination_inp);
    } // open_destination_replica

    int close_replica(RsComm& _comm, const int _fd, const int _status)
    {
        auto& l1desc = L1desc[_fd];
        openedDataObjInp_t close_inp{};
        close_inp.l1descInx = _fd;
        l1desc.oprStatus = _status;

        irods::at_scope_exit free_cond_input{[&close_inp] { clearKeyVal( &close_inp.condInput ); }};

        auto l1desc_cond_input = irods::experimental::make_key_value_proxy(l1desc.dataObjInp->condInput);
        auto close_cond_input = irods::experimental::make_key_value_proxy(close_inp.condInput);
        if (l1desc_cond_input.contains(IN_PDMO_KW)) {
            close_cond_input[IN_PDMO_KW] = l1desc_cond_input.at(IN_PDMO_KW);
        }

        return rsDataObjClose(&_comm, &close_inp);
    } // close_replica

    int move_data(RsComm& _comm, dataObjInp_t& source_inp, dataObjInp_t& destination_inp)
    {
        // Open source replica
        int source_fd = open_source_replica(_comm, source_inp);
        if (source_fd < 3) {
            THROW(source_fd, "Failed opening source replica");
        }

        // Open destination replica
        int destination_fd = open_destination_replica(_comm, destination_inp);
        if (destination_fd < 3) {
            close_replica(_comm, source_fd, source_fd);
            THROW(destination_fd, "Failed opening destination replica");
        }
        auto& destination_l1desc = L1desc[destination_fd];
        destination_l1desc.srcL1descInx = source_fd;

        // Copy data from source to destination
        const int status = dataObjCopy(&_comm, destination_fd);
        if (status < 0) {
            rodsLog(LOG_ERROR, "[%s] - dataObjCopy failed for [%s]", __FUNCTION__, destination_inp.objPath);
        }
        destination_l1desc.bytesWritten = destination_l1desc.dataObjInfo->dataSize;

        // Close destination replica
        int close_status = close_replica(_comm, destination_fd, status);
        if (close_status < 0) {
            rodsLog(LOG_ERROR,
                    "[%s] - closing destination replica [%s] failed with [%d]",
                    __FUNCTION__, destination_inp.objPath, close_status);
        }
        // Close source replica
        close_status = close_replica(_comm, source_fd, status);
        if (close_status < 0) {
            rodsLog(LOG_ERROR,
                    "[%s] - closing source replica [%s] failed with [%d]",
                    __FUNCTION__, source_inp.objPath, close_status);
        }
        return status;
    } // move_data

    auto update_all_existing_replicas(
        RsComm& _comm,
        dataObjInp_t& _source_inp,
        dataObjInp_t& _destination_inp,
        data_object_proxy& _obj) -> int
    {
        int last_ec = 0;
        for (const auto& r : _obj.replicas()) {
            irods::log(LOG_DEBUG, fmt::format(
                "[{}:{}] - hier:[{}],status:[{}],vote:[{}]",
                __FUNCTION__, __LINE__, r.hierarchy(), r.replica_status(), r.vote()));

            if (GOOD_REPLICA == (r.replica_status() & 0x0F)) {
                continue;
            }

            if (r.vote() > irv::vote::zero) {
                irods::experimental::key_value_proxy{_destination_inp.condInput}[RESC_HIER_STR_KW] = r.hierarchy();
                if (const int ec = move_data(_comm, _source_inp, _destination_inp); ec < 0) {
                    last_ec = ec;
                }
            }
        }
        return last_ec;
    } // update_all_existing_replicas

    auto create_single_replica(
        RsComm& _comm,
        dataObjInp_t& _source_inp,
        dataObjInp_t& _destination_inp,
        data_object_proxy& _obj) -> int
    {
        auto source_cond_input = irods::experimental::make_key_value_proxy(_source_inp.condInput);
        auto destination_cond_input  = irods::experimental::make_key_value_proxy(_destination_inp.condInput);

        if (source_cond_input.at(RESC_HIER_STR_KW) == destination_cond_input.at(RESC_HIER_STR_KW)) {
            irods::log(LOG_NOTICE, fmt::format(
                "[{}] - source and destination replicas are the same, path:[{}],source:[{}],dest:[{}]",
                __FUNCTION__, __LINE__,
                _obj.logical_path(),
                source_cond_input.at(RESC_HIER_STR_KW).value(),
                destination_cond_input.at(RESC_HIER_STR_KW).value()));
            return 0;
        }

        // TODO: #4010 - This short-circuits resource logic for handling good replicas
        for (const auto& r : _obj.replicas()) {
            if (r.hierarchy() == destination_cond_input.at(RESC_HIER_STR_KW) && r.replica_status() == GOOD_REPLICA) {
                return 0;
            }
        }

        return move_data(_comm, _source_inp, _destination_inp);
    } // create_single_replica

    int singleL1Copy(
        RsComm *rsComm,
        dataCopyInp_t& dataCopyInp) {

        int trans_buff_size;
        try {
            trans_buff_size = irods::get_advanced_setting<const int>(irods::CFG_TRANS_BUFFER_SIZE_FOR_PARA_TRANS) * 1024 * 1024;
        } catch ( const irods::exception& e ) {
            irods::log(e);
            return e.code();
        }

        dataOprInp_t* dataOprInp = &dataCopyInp.dataOprInp;
        int destination_fd = dataCopyInp.portalOprOut.l1descInx;
        int source_fd = L1desc[destination_fd].srcL1descInx;

        openedDataObjInp_t dataObjReadInp{};
        dataObjReadInp.l1descInx = source_fd;
        dataObjReadInp.len = trans_buff_size;

        bytesBuf_t dataObjReadInpBBuf{};
        dataObjReadInpBBuf.buf = malloc(dataObjReadInp.len);
        dataObjReadInpBBuf.len = dataObjReadInp.len;
        const irods::at_scope_exit free_data_obj_read_inp_bbuf{[&dataObjReadInpBBuf]() {
            free(dataObjReadInpBBuf.buf);
        }};

        openedDataObjInp_t dataObjWriteInp{};
        dataObjWriteInp.l1descInx = destination_fd;

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
    RsComm *rsComm,
    dataObjInp_t *dataObjInp,
    transferStat_t **transStat)
{
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
    int status = resolvePathInSpecColl( rsComm, dataObjInp->objPath, READ_COLL_PERM, 0, &dataObjInfo );
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

        // Separate the source and destination inputs as the API packages them together via keywords
        auto source_inp = init_source_replica_input(*dataObjInp);
        auto destination_inp = init_destination_replica_input(*dataObjInp);

        irods::at_scope_exit clean_up_cond_inputs{[&]
            {
                clearKeyVal(&source_inp.condInput);
                clearKeyVal(&destination_inp.condInput);

                rmKeyVal(&dataObjInp->condInput, IN_REPL_KW);
            }
        };

        auto [obj, obj_lm] = irods::experimental::data_object::make_data_object_proxy(*rsComm, source_inp);
        if (!obj.in_catalog()) {
            THROW(SYS_INVALID_INPUT_PARAM, fmt::format("data object [{}] does not exist", obj.logical_path()));
        }

        // populate resolved resource hierarchies for input to open
        resolve_hierarchy_for_source(*rsComm, source_inp, obj);
        resolve_hierarchy_for_destination(*rsComm, destination_inp, obj);

        if (irods::experimental::key_value_proxy{source_inp.condInput}.contains(ALL_KW)) {
            status = update_all_existing_replicas(*rsComm, source_inp, destination_inp, obj);
        }
        else {
            status = create_single_replica(*rsComm, source_inp, destination_inp, obj);
        }
    }
    catch (const irods::exception& e) {
        irods::log(e);
        status = e.code();
    }

    if (status < 0 && status != DIRECT_ARCHIVE_ACCESS) {
        rodsLog(LOG_NOTICE, "%s - Failed to replicate data object. status:[%d]",
                __FUNCTION__, status);
    }
    return (status == DIRECT_ARCHIVE_ACCESS) ? 0 : status;
} // rsDataObjRepl

int dataObjCopy(
    RsComm* rsComm,
    int _destination_l1descInx) {

    int srcRemoteFlag{};
    int source_fd = L1desc[_destination_l1descInx].srcL1descInx;
    int srcL3descInx = L1desc[source_fd].l3descInx;
    if (L1desc[source_fd].remoteZoneHost) {
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
                        L1desc[source_fd].dataObjInfo->objPath );
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
            int status = preProcParaGet( rsComm, source_fd, &portalOprOut );
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaGet error for %s",
                        __FUNCTION__,
                        L1desc[source_fd].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = source_fd;
        }
        if ( destRemoteFlag == LOCAL_HOST ) {
            addKeyVal( &dataCopyInp.dataOprInp.condInput, EXEC_LOCALLY_KW, "" );
        }
    }
    else {
        /* remote to remote */
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_LOCAL_OPR );
        if (L1desc[_destination_l1descInx].dataObjInp->numThreads > 0) {
            int status = preProcParaGet(rsComm, source_fd, &portalOprOut);
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaGet error for %s",
                        __FUNCTION__,
                        L1desc[source_fd].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = source_fd;
        }
    }

    if (getValByKey(&L1desc[_destination_l1descInx].dataObjInp->condInput, NO_CHK_COPY_LEN_KW)) {
        addKeyVal(&dataCopyInp.dataOprInp.condInput, NO_CHK_COPY_LEN_KW, "");
        if (L1desc[_destination_l1descInx].dataObjInp->numThreads > 1) {
            L1desc[_destination_l1descInx].dataObjInp->numThreads = 1;
            L1desc[source_fd].dataObjInp->numThreads = 1;
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

int unbunAndStageBunfileObj(RsComm* rsComm, const char* _logical_path, char** outCacheRescName)
{
    /* query the bundle dataObj */
    dataObjInp_t dataObjInp{};
    rstrcpy( dataObjInp.objPath, _logical_path, MAX_NAME_LEN );

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
    RsComm* rsComm,
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
