#include "dataGet.h"
#include "dataObjClose.h"
#include "dataObjGet.h"
#include "dataObjOpen.h"
#include "fileGet.h"
#include "getRemoteZoneResc.h"
#include "objMetaOpr.hpp"
#include "physPath.hpp"
#include "rcGlobalExtern.h"
#include "rodsLog.h"
#include "rsApiHandler.hpp"
#include "rsDataGet.hpp"
#include "rsDataObjClose.hpp"
#include "rsDataObjGet.hpp"
#include "rsDataObjRead.hpp"
#include "rsDataObjOpen.hpp"
#include "rsFileLseek.hpp"
#include "rsGlobalExtern.hpp"
#include "specColl.hpp"

#include "irods_at_scope_exit.hpp"
#include "irods_resource_backport.hpp"
#include "irods_resource_redirect.hpp"
#include "resolve_resource_hierarchy.hpp"

namespace
{
    auto get_checksum_string(rsComm_t& _comm, dataObjInp_t& _inp, const int _l1desc_inx) -> char*
    {
        auto replica = irods::experimental::replica::make_replica_proxy(*L1desc[_l1desc_inx].dataObjInfo);
        copyKeyVal(&_inp.condInput, replica.cond_input().get());

        auto cond_input = irods::experimental::key_value_proxy(_inp.condInput);
        if (!cond_input.contains(VERIFY_CHKSUM_KW)) {
            return nullptr;
        }

        char* checksum_string = nullptr;
        if (!replica.checksum().empty()) {
            checksum_string = strdup(replica.checksum().data());
        }
        else {
            if (const int ec = dataObjChksumAndReg(&_comm, replica.get(), &checksum_string); ec < 0) {
                THROW(ec, "failed in dataObjChksumAndReg");
            }
            replica.checksum(checksum_string);
        }
        return checksum_string;
    } // get_checksum_string

    auto single_buffer_get(rsComm_t& _comm, dataObjInp_t& _inp, bytesBuf_t* _bytes_buf) -> int
    {
        int l1desc_inx = rsDataObjOpen(&_comm, &_inp);
        if (l1desc_inx < 0) {
            return l1desc_inx;
        }
        L1desc[l1desc_inx].oprType = GET_OPR;

        char* checksum_string = get_checksum_string(_comm, _inp, l1desc_inx);
        irods::at_scope_exit free_checksum_string{[&checksum_string] { free(checksum_string); }};

        _bytes_buf->len = L1desc[l1desc_inx].dataObjInfo->dataSize;
        _bytes_buf->buf = malloc(_bytes_buf->len);
        std::memset(_bytes_buf->buf, 0, _bytes_buf->len);

        int bytes_read = 0;
        {
            openedDataObjInp_t read_inp{};
            read_inp.len = _bytes_buf->len;
            read_inp.l1descInx = l1desc_inx;
            bytes_read = rsDataObjRead(&_comm, &read_inp, _bytes_buf);
            if (bytes_read < 0) {
                irods::log(LOG_NOTICE, fmt::format("[{}] - failed to read [{}], code:[{}]", __FUNCTION__, _inp.objPath, bytes_read));
            }
        }

        {
            openedDataObjInp_t close_inp{};
            close_inp.l1descInx = l1desc_inx;
            if (const int ec = rsDataObjClose(&_comm, &close_inp); ec <0) {
                irods::log(LOG_NOTICE, fmt::format("[{}] - failed to close [{}], code:[{}]", __FUNCTION__, _inp.objPath, ec));
                return bytes_read < 0 ? bytes_read : ec;
            }
        }

        return bytes_read < 0 ? bytes_read : 0;
    } // single_buffer_get

    auto parallel_get(rsComm_t& _comm, dataObjInp_t& _inp, portalOprOut_t** _portal_output) -> int
    {
        int l1desc_inx = rsDataObjOpen(&_comm, &_inp);
        if (l1desc_inx < 0) {
            return l1desc_inx;
        }
        auto& l1desc = L1desc[l1desc_inx];
        l1desc.oprType = GET_OPR;

        // Structured files are special
        if (getStructFileType(l1desc.dataObjInfo->specColl) >= 0 && l1desc.l3descInx > 0) {
            /* l3descInx == 0 if included */
            *_portal_output = ( portalOprOut_t * ) malloc( sizeof( portalOprOut_t ) );
            bzero( *_portal_output,  sizeof( portalOprOut_t ) );
            ( *_portal_output )->l1descInx = l1desc_inx;
            return l1desc_inx;
        }

        char* checksum_string = get_checksum_string(_comm, _inp, l1desc_inx);
        irods::at_scope_exit free_checksum_string{[&checksum_string] { free(checksum_string); }};

        if (const int ec = preProcParaGet(&_comm, l1desc_inx, _portal_output); ec < 0) {
            openedDataObjInp_t dataObjCloseInp{};
            dataObjCloseInp.l1descInx = l1desc_inx;
            rsDataObjClose(&_comm, &dataObjCloseInp);
            return ec;
        }

        if (checksum_string) {
            rstrcpy((*_portal_output)->chksum, checksum_string, NAME_LEN);
        }

        // return portalOprOut to the client and wait for the rcOprComplete call. That is when the parallel I/O is done
        if (sendAndRecvBranchMsg(&_comm, _comm.apiInx, l1desc_inx, ( void * ) * _portal_output, nullptr) < 0) {
            openedDataObjInp_t close_inp{};
            close_inp.l1descInx = l1desc_inx;
            rsDataObjClose(&_comm, &close_inp);
        }

        return SYS_NO_HANDLER_REPLY_MSG;
    } // parallel_get
} // anonymous namespace

int rsDataObjGet(rsComm_t *rsComm, dataObjInp_t *dataObjInp, portalOprOut_t **portalOprOut, bytesBuf_t *dataObjOutBBuf)
{
    rodsServerHost_t *rodsServerHost;
    specCollCache_t *specCollCache = NULL;
    if ( dataObjOutBBuf == NULL ) {
        rodsLog( LOG_ERROR, "dataObjOutBBuf was null in call to rsDataObjGet." );
        return SYS_INTERNAL_NULL_INPUT_ERR;
    }

    remove_trailing_path_separators(dataObjInp->objPath);

    resolveLinkedPath( rsComm, dataObjInp->objPath, &specCollCache, &dataObjInp->condInput );

    int remoteFlag = getAndConnRemoteZone( rsComm, dataObjInp, &rodsServerHost, REMOTE_OPEN );
    if ( remoteFlag < 0 ) {
        return remoteFlag;
    }
    else if ( remoteFlag != LOCAL_HOST ) {
        int status = _rcDataObjGet( rodsServerHost->conn, dataObjInp, portalOprOut, dataObjOutBBuf );

        if ( status < 0 ) {
            return status;
        }

        if ( status == 0 || dataObjOutBBuf->len > 0 ) {
            /* data included in buf */
            return status;
        }
        else if ( !( *portalOprOut ) ) {
            rodsLog( LOG_ERROR, "_rcDataObjGet returned a %d status code, but left portalOprOut null.", status );
            return SYS_INVALID_PORTAL_OPR;
        }
        else {
            /* have to allocate a local l1descInx to keep track of things
             * since the file is in remote zone. It sets remoteL1descInx,
             * oprType = REMOTE_ZONE_OPR and remoteZoneHost so that
             * rsComplete knows what to do */
            int l1descInx = allocAndSetL1descForZoneOpr(
                            ( *portalOprOut )->l1descInx, dataObjInp, rodsServerHost, NULL );
            if ( l1descInx < 0 ) {
                return l1descInx;
            }
            ( *portalOprOut )->l1descInx = l1descInx;
            return status;
        }
    }

    // =-=-=-=-=-=-=-
    // working on the "home zone", determine if we need to redirect to a different
    // server in this zone for this operation.  if there is a RESC_HIER_STR_KW then
    // we know that the redirection decision has already been made
    try {
        auto [obj, lm] = irods::experimental::data_object::make_data_object_proxy(*rsComm, *dataObjInp);
        if (!obj.in_catalog()) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}:{}] - data object [{}] does not exist",
                __FUNCTION__, __LINE__, obj.logical_path()));
            return SYS_INVALID_INPUT_PARAM;
        }

        auto cond_input = irods::experimental::key_value_proxy(dataObjInp->condInput);
        if (!cond_input.contains(RESC_HIER_STR_KW)) {
            const auto winner = irods::experimental::resource::resolve_resource_hierarchy(*rsComm, irods::OPEN_OPERATION, *dataObjInp, obj);
            cond_input[RESC_HIER_STR_KW] = std::get<std::string>(winner);
        }

        bool fits_inside_single_buffer = false;
        const auto winner_id = resc_mgr.hier_to_leaf_id(cond_input.at(RESC_HIER_STR_KW).value());
        for (auto&& replica : obj.replicas()) {
            if (replica.resource_id() == winner_id) {
                const int buffer_size = irods::get_advanced_setting<const int>(irods::CFG_MAX_SIZE_FOR_SINGLE_BUFFER) * 1024 * 1024;
                fits_inside_single_buffer = replica.size() <= buffer_size && UNKNOWN_FILE_SZ != replica.size();
                break;
            }
        }

        if (fits_inside_single_buffer) {
            return single_buffer_get(*rsComm, *dataObjInp, dataObjOutBBuf);
        }

        return parallel_get(*rsComm, *dataObjInp, portalOprOut);
    }
    catch (const irods::exception& e) {
        irods::log(e);
        return e.code();
    }
} // rsDataObjGet

/* preProcParaGet - preprocessing for parallel get. Basically it calls
 * rsDataGet to setup portalOprOut with the resource server.
 */
int
preProcParaGet( rsComm_t *rsComm, int l1descInx, portalOprOut_t **portalOprOut ) {
    int status;
    dataOprInp_t dataOprInp;

    initDataOprInp( &dataOprInp, l1descInx, GET_OPR );
    /* add RESC_HIER_STR_KW for getNumThreads */
    if ( L1desc[l1descInx].dataObjInfo != NULL ) {
        //addKeyVal (&dataOprInp.condInput, RESC_NAME_KW,
        //           L1desc[l1descInx].dataObjInfo->rescInfo->rescName);
        addKeyVal( &dataOprInp.condInput, RESC_HIER_STR_KW,
                   L1desc[l1descInx].dataObjInfo->rescHier );
    }
    if ( L1desc[l1descInx].remoteZoneHost != NULL ) {
        status =  remoteDataGet( rsComm, &dataOprInp, portalOprOut,
                                 L1desc[l1descInx].remoteZoneHost );
    }
    else {
        status =  rsDataGet( rsComm, &dataOprInp, portalOprOut );
    }

    if ( status >= 0 ) {
        ( *portalOprOut )->l1descInx = l1descInx;
    }
    clearKeyVal( &dataOprInp.condInput );
    return status;
}

