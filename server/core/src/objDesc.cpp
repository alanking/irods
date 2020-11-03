#include "collection.hpp"
#include "dataObjClose.h"
#include "dataObjOpr.hpp"
#include "fileChksum.h"
#include "genQuery.h"
#include "modDataObjMeta.h"
#include "objDesc.hpp"
#include "objMetaOpr.hpp"
#include "rcGlobalExtern.h"
#include "rcMisc.h"
#include "resource.hpp"
#include "rodsDef.h"
#include "rodsDef.h"
#include "rsDataObjClose.hpp"
#include "rsGenQuery.hpp"
#include "rsGetHierFromLeafId.hpp"
#include "rsGlobalExtern.hpp"
#include "rsQuerySpecColl.hpp"

#include "get_hier_from_leaf_id.h"
#include "irods_hierarchy_parser.hpp"
#include "irods_re_structs.hpp"
#include "irods_resource_backport.hpp"
#include "irods_stacktrace.hpp"
#include "key_value_proxy.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "replica_proxy.hpp"

int
initL1desc() {
    memset( L1desc, 0, sizeof( L1desc ) );
    return 0;
}

int
allocL1desc() {
    int i;

    for ( i = 3; i < NUM_L1_DESC; i++ ) {
        if ( L1desc[i].inuseFlag <= FD_FREE ) {
            L1desc[i].inuseFlag = FD_INUSE;
            return i;
        };
    }

    rodsLog( LOG_NOTICE,
             "allocL1desc: out of L1desc" );

    return SYS_OUT_OF_FILE_DESC;
}

int
isL1descInuse() {
    int i;

    for ( i = 3; i < NUM_L1_DESC; i++ ) {
        if ( L1desc[i].inuseFlag == FD_INUSE ) {
            return 1;
        };
    }
    return 0;
}

int
initSpecCollDesc() {
    memset( SpecCollDesc, 0, sizeof( SpecCollDesc ) );
    return 0;
}

int
allocSpecCollDesc() {
    int i;

    for ( i = 1; i < NUM_SPEC_COLL_DESC; i++ ) {
        if ( SpecCollDesc[i].inuseFlag <= FD_FREE ) {
            SpecCollDesc[i].inuseFlag = FD_INUSE;
            return i;
        };
    }

    rodsLog( LOG_NOTICE,
             "allocSpecCollDesc: out of SpecCollDesc" );

    return SYS_OUT_OF_FILE_DESC;
}

int
freeSpecCollDesc( int specCollInx ) {
    if ( specCollInx < 1 || specCollInx >= NUM_SPEC_COLL_DESC ) {
        rodsLog( LOG_NOTICE,
                 "freeSpecCollDesc: specCollInx %d out of range", specCollInx );
        return SYS_FILE_DESC_OUT_OF_RANGE;
    }

    if ( SpecCollDesc[specCollInx].dataObjInfo != NULL ) {
        freeDataObjInfo( SpecCollDesc[specCollInx].dataObjInfo );
    }

    memset( &SpecCollDesc[specCollInx], 0, sizeof( specCollDesc_t ) );

    return 0;
}

int
closeAllL1desc( rsComm_t *rsComm ) {
    int i;

    if ( rsComm == NULL ) {
        return 0;
    }
    for ( i = 3; i < NUM_L1_DESC; i++ ) {
        if ( L1desc[i].inuseFlag == FD_INUSE &&
                L1desc[i].l3descInx > 2 ) {
            l3Close( rsComm, i );
        }
    }
    return 0;
}

int
freeL1desc( int l1descInx ) {
    if ( l1descInx < 3 || l1descInx >= NUM_L1_DESC ) {
        rodsLog( LOG_NOTICE, "freeL1desc: l1descInx %d out of range", l1descInx );
        return SYS_FILE_DESC_OUT_OF_RANGE;
    }

    if ( L1desc[l1descInx].dataObjInfo != NULL ) {
        freeDataObjInfo( L1desc[l1descInx].dataObjInfo );
    }

    if ( L1desc[l1descInx].otherDataObjInfo != NULL ) {
        freeAllDataObjInfo( L1desc[l1descInx].otherDataObjInfo );
    }

    if ( L1desc[l1descInx].replDataObjInfo != NULL ) {
        freeDataObjInfo( L1desc[l1descInx].replDataObjInfo );
    }

    if ( L1desc[l1descInx].dataObjInpReplFlag == 1 &&
            L1desc[l1descInx].dataObjInp != NULL ) {
        clearDataObjInp( L1desc[l1descInx].dataObjInp );
        free( L1desc[l1descInx].dataObjInp );
    }

    L1desc[l1descInx].replica_token.clear();

    memset( &L1desc[l1descInx], 0, sizeof( l1desc_t ) );

    return 0;
}

int
initDataObjInfoWithInp( dataObjInfo_t *dataObjInfo, dataObjInp_t *dataObjInp ) {
    namespace ix = irods::experimental;

    if (!dataObjInp || !dataObjInfo) {
        rodsLog(LOG_ERROR, "[%s] - null input", __FUNCTION__);
        return SYS_INTERNAL_NULL_INPUT_ERR;
    }
    auto kvp = ix::make_key_value_proxy(dataObjInp->condInput);
    memset( dataObjInfo, 0, sizeof( dataObjInfo_t ) );

    rstrcpy( dataObjInfo->objPath, dataObjInp->objPath, MAX_NAME_LEN );

    if (kvp.contains(DATA_ID_KW)) {
        dataObjInfo->dataId = std::atoll(kvp.at(DATA_ID_KW).value().data());
    }

    if (kvp.contains(RESC_NAME_KW)) {
        const auto resc_name = kvp.at(RESC_NAME_KW).value();
        rstrcpy(dataObjInfo->rescName, resc_name.data(), NAME_LEN);
        if (!kvp.contains(RESC_HIER_STR_KW)) {
            rstrcpy( dataObjInfo->rescHier, resc_name.data(), MAX_NAME_LEN );
        }
    }

    if (kvp.contains(RESC_HIER_STR_KW)) {
        auto hier = kvp.at(RESC_HIER_STR_KW).value();
        rstrcpy(dataObjInfo->rescHier, hier.data(), MAX_NAME_LEN);
    }

    irods::error ret = resc_mgr.hier_to_leaf_id(dataObjInfo->rescHier,dataObjInfo->rescId);
    if( !ret.ok() ) {
        irods::log(PASS(ret));
    }

    snprintf( dataObjInfo->dataMode, SHORT_STR_LEN, "%d", dataObjInp->createMode );

    if (kvp.contains(DATA_TYPE_KW)) {
        auto data_type = kvp.at(DATA_TYPE_KW).value();
        rstrcpy(dataObjInfo->dataType, data_type.data(), NAME_LEN);
    }
    else {
        rstrcpy(dataObjInfo->dataType, "generic", NAME_LEN);
    }

    if (kvp.contains(FILE_PATH_KW)) {
        auto file_path = kvp.at(FILE_PATH_KW).value();
        rstrcpy( dataObjInfo->filePath, file_path.data(), MAX_NAME_LEN );
    }

    return 0;
}

int
getL1descIndexByDataObjInfo( const dataObjInfo_t * dataObjInfo ) {
    int index;
    for ( index = 3; index < NUM_L1_DESC; index++ ) {
        if ( L1desc[index].dataObjInfo == dataObjInfo ) {
            return index;
        }
    }
    return -1;
}

/* getNumThreads - get the number of threads.
 * inpNumThr - 0 - server decide
 *             < 0 - NO_THREADING
 *             > 0 - num of threads wanted
 */

int
getNumThreads( rsComm_t *rsComm, rodsLong_t dataSize, int inpNumThr,
               keyValPair_t *condInput, char *destRescHier, char *srcRescHier, int oprType ) {
    ruleExecInfo_t rei;
    dataObjInp_t doinp;
    int status;
    int numDestThr = -1;
    int numSrcThr = -1;


    if ( inpNumThr == NO_THREADING ) {
        return 0;
    }

    if ( dataSize < 0 ) {
        return 0;
    }

    if ( dataSize <= MIN_SZ_FOR_PARA_TRAN ) {
        if ( inpNumThr > 0 ) {
            inpNumThr = 1;
        }
        else {
            return 0;
        }
    }

    if ( getValByKey( condInput, NO_PARA_OP_KW ) != NULL ) {
        /* client specify no para opr */
        return 1;
    }

    memset( &doinp, 0, sizeof( doinp ) );
    doinp.numThreads = inpNumThr;

    doinp.dataSize = dataSize;
    doinp.oprType = oprType;

    initReiWithDataObjInp( &rei, rsComm, &doinp );

    if (destRescHier && strlen(destRescHier)) {

        // get resource (hierarchy) location
        std::string location;
        irods::error ret = irods::get_loc_for_hier_string( destRescHier, location );
        if ( !ret.ok() ) {
            irods::log( PASSMSG( "getNumThreads - failed in get_loc_for_hier_string", ret ) );
            clearKeyVal(rei.condInputData);
            free(rei.condInputData);
            return -1;
        }

        irods::error err = irods::is_hier_live( destRescHier );
        if ( err.ok() ) {
            // fill rei.condInputData with resource properties
            ret = irods::get_resc_properties_as_kvp(destRescHier, rei.condInputData);
            if ( !ret.ok() ) {
                irods::log( PASSMSG( "getNumThreads - failed in get_resc_properties_as_kvp", ret ) );
            }

            // PEP
            status = applyRule( "acSetNumThreads", NULL, &rei, NO_SAVE_REI );

            if ( status < 0 ) {
                rodsLog( LOG_ERROR,
                         "getNumThreads: acSetNumThreads error, status = %d",
                         status );
            }
            else {

                numDestThr = rei.status;
                if ( numDestThr == 0 ) {
                    clearKeyVal(rei.condInputData);
                    free(rei.condInputData);
                    return 0;
                }
                else if ( numDestThr == 1 && srcRescHier == NULL &&
                          isLocalHost( location.c_str() ) ) {
                    /* one thread and resource on local host */
                    clearKeyVal(rei.condInputData);
                    free(rei.condInputData);
                    return 0;
                }
            }
        }
    }

    if (destRescHier && strlen(destRescHier) && srcRescHier && strlen(srcRescHier)) {
        if ( numDestThr > 0 && strcmp( destRescHier, srcRescHier ) == 0 ) {
            clearKeyVal(rei.condInputData);
            free(rei.condInputData);

            return numDestThr;
        }

        // get resource (hierarchy) location
        std::string location;
        irods::error ret = irods::get_loc_for_hier_string( destRescHier, location );
        if ( !ret.ok() ) {
            irods::log( PASSMSG( "getNumThreads - failed in get_loc_for_hier_string", ret ) );
            clearKeyVal(rei.condInputData);
            free(rei.condInputData);

            return -1;
        }

        irods::error err = irods::is_hier_live( srcRescHier );
        if ( err.ok() ) {
            // fill rei.condInputData with resource properties
            ret = irods::get_resc_properties_as_kvp(destRescHier, rei.condInputData);
            if ( !ret.ok() ) {
                irods::log( PASSMSG( "getNumThreads - failed in get_resc_properties_as_kvp", ret ) );
            }

            // PEP
            status = applyRule( "acSetNumThreads", NULL, &rei, NO_SAVE_REI );

            if ( status < 0 ) {
                rodsLog( LOG_ERROR,
                         "getNumThreads: acSetNumThreads error, status = %d",
                         status );
            }
            else {
                numSrcThr = rei.status;
                if ( numSrcThr == 0 ) {
                    clearKeyVal(rei.condInputData);
                    free(rei.condInputData);

                    return 0;
                }
            }
        }
    }

    if ( numDestThr > 0 ) {
        clearKeyVal(rei.condInputData);
        free(rei.condInputData);
        if ( getValByKey( condInput, RBUDP_TRANSFER_KW ) != NULL ) {
            return 1;
        }
        else {
            return numDestThr;
        }
    }
    if ( numSrcThr > 0 ) {
        clearKeyVal(rei.condInputData);
        free(rei.condInputData);
        if ( getValByKey( condInput, RBUDP_TRANSFER_KW ) != NULL ) {
            return 1;
        }
        else {
            return numSrcThr;
        }
    }
    /* should not be here. do one with no resource */
    status = applyRule( "acSetNumThreads", NULL, &rei, NO_SAVE_REI );
    clearKeyVal(rei.condInputData);
    free(rei.condInputData);
    if ( status < 0 ) {
        rodsLog( LOG_ERROR,
                 "getNumThreads: acGetNumThreads error, status = %d",
                 status );
        return 0;
    }
    else {
        if ( rei.status > 0 ) {
            return rei.status;
        }
        else {
            return 0;
        }
    }
}

int
initDataOprInp( dataOprInp_t *dataOprInp, int l1descInx, int oprType ) {
    dataObjInfo_t *dataObjInfo;
    dataObjInp_t  *dataObjInp;
    char *tmpStr;


    dataObjInfo = L1desc[l1descInx].dataObjInfo;
    dataObjInp = L1desc[l1descInx].dataObjInp;

    memset( dataOprInp, 0, sizeof( dataOprInp_t ) );

    dataOprInp->oprType = oprType;
    dataOprInp->numThreads = dataObjInp->numThreads;
    dataOprInp->offset = dataObjInp->offset;
    if ( oprType == PUT_OPR ) {
        if ( dataObjInp->dataSize > 0 ) {
            dataOprInp->dataSize = dataObjInp->dataSize;
        }
        dataOprInp->destL3descInx = L1desc[l1descInx].l3descInx;
    }
    else if ( oprType == GET_OPR ) {
        if ( dataObjInfo->dataSize > 0 ) {
            dataOprInp->dataSize = dataObjInfo->dataSize;
        }
        else {
            dataOprInp->dataSize = dataObjInp->dataSize;
        }
        dataOprInp->srcL3descInx = L1desc[l1descInx].l3descInx;
    }
    else if ( oprType == SAME_HOST_COPY_OPR ) {
        int srcL1descInx = L1desc[l1descInx].srcL1descInx;
        int srcL3descInx = L1desc[srcL1descInx].l3descInx;
        dataOprInp->dataSize = L1desc[srcL1descInx].dataObjInfo->dataSize;
        dataOprInp->destL3descInx = L1desc[l1descInx].l3descInx;
        dataOprInp->srcL3descInx = srcL3descInx;
    }
    else if ( oprType == COPY_TO_REM_OPR ) {
        int srcL1descInx = L1desc[l1descInx].srcL1descInx;
        int srcL3descInx = L1desc[srcL1descInx].l3descInx;
        dataOprInp->dataSize = L1desc[srcL1descInx].dataObjInfo->dataSize;
        dataOprInp->srcL3descInx = srcL3descInx;
    }
    else if ( oprType == COPY_TO_LOCAL_OPR ) {
        int srcL1descInx = L1desc[l1descInx].srcL1descInx;
        dataOprInp->dataSize = L1desc[srcL1descInx].dataObjInfo->dataSize;
        dataOprInp->destL3descInx = L1desc[l1descInx].l3descInx;
    }
    if ( getValByKey( &dataObjInp->condInput, STREAMING_KW ) != NULL ) {
        addKeyVal( &dataOprInp->condInput, STREAMING_KW, "" );
    }

    if ( getValByKey( &dataObjInp->condInput, NO_PARA_OP_KW ) != NULL ) {
        addKeyVal( &dataOprInp->condInput, NO_PARA_OP_KW, "" );
    }

    if ( getValByKey( &dataObjInp->condInput, RBUDP_TRANSFER_KW ) != NULL ) {

        /* only do unix fs */
        // JMC - legacy resource - int rescTypeInx = dataObjInfo->rescInfo->rescTypeInx;
        // JMC - legacy resource - if (RescTypeDef[rescTypeInx].driverType == UNIX_FILE_TYPE)
        std::string type;
        irods::error err = irods::get_resc_type_for_hier_string( dataObjInfo->rescHier, type );

        if ( !err.ok() ) {
            irods::log( PASS( err ) );
        }
        else {
            if ( irods::RESOURCE_TYPE_NATIVE == type ) { // JMC ::
                addKeyVal( &dataOprInp->condInput, RBUDP_TRANSFER_KW, "" );
            }
        }
    }

    if ( getValByKey( &dataObjInp->condInput, VERY_VERBOSE_KW ) != NULL ) {
        addKeyVal( &dataOprInp->condInput, VERY_VERBOSE_KW, "" );
    }

    if ( ( tmpStr = getValByKey( &dataObjInp->condInput, RBUDP_SEND_RATE_KW ) ) !=
            NULL ) {
        addKeyVal( &dataOprInp->condInput, RBUDP_SEND_RATE_KW, tmpStr );
    }

    if ( ( tmpStr = getValByKey( &dataObjInp->condInput, RBUDP_PACK_SIZE_KW ) ) !=
            NULL ) {
        addKeyVal( &dataOprInp->condInput, RBUDP_PACK_SIZE_KW, tmpStr );
    }

    return 0;
}

int
convL3descInx( int l3descInx ) {
    if ( l3descInx <= 2 || FileDesc[l3descInx].inuseFlag == 0 ||
            FileDesc[l3descInx].rodsServerHost == NULL ) {
        return l3descInx;
    }

    if ( FileDesc[l3descInx].rodsServerHost->localFlag == LOCAL_HOST ) {
        return l3descInx;
    }
    else {
        return FileDesc[l3descInx].fd;
    }
}

int allocCollHandle() {
    // look for a free collHandle_t
    for (std::vector<collHandle_t>::iterator it = CollHandle.begin(); it != CollHandle.end(); ++it) {
    	if (it->inuseFlag <= FD_FREE) {
    		it->inuseFlag = FD_INUSE;
    		return it - CollHandle.begin();
    	}
    }

    // if none found make a new one
    collHandle_t my_coll_handle;
    memset(&my_coll_handle, 0, sizeof(collHandle_t));

    // mark as in use
    my_coll_handle.inuseFlag = FD_INUSE;

    // add to vector
    CollHandle.push_back(my_coll_handle);

    // return index
    return CollHandle.size() - 1;
}

int freeCollHandle( int handleInx ) {
    if ( handleInx < 0 || static_cast<std::size_t>(handleInx) >= CollHandle.size() ) {
        rodsLog( LOG_NOTICE,
                 "freeCollHandle: handleInx %d out of range", handleInx );
        return SYS_FILE_DESC_OUT_OF_RANGE;
    }

    /* don't free specColl. It is in cache */
    clearCollHandle( &CollHandle[handleInx], 1 );
    memset( &CollHandle[handleInx], 0, sizeof( collHandle_t ) );

    return 0;
}

int
rsInitQueryHandle( queryHandle_t *queryHandle, rsComm_t *rsComm ) {
    if ( queryHandle == NULL || rsComm == NULL ) {
        return USER__NULL_INPUT_ERR;
    }

    queryHandle->conn = rsComm;
    queryHandle->connType = RS_COMM;
    queryHandle->querySpecColl = ( funcPtr ) rsQuerySpecColl;
    queryHandle->genQuery = ( funcPtr ) rsGenQuery;
    queryHandle->getHierForId = ( funcPtr ) rsGetHierFromLeafId;

    return 0;
}

int
allocAndSetL1descForZoneOpr( int remoteL1descInx, dataObjInp_t *dataObjInp,
                             rodsServerHost_t *remoteZoneHost, openStat_t *openStat ) {
    int l1descInx;
    dataObjInfo_t *dataObjInfo;

    l1descInx = allocL1desc();
    if ( l1descInx < 0 ) {
        return l1descInx;
    }
    L1desc[l1descInx].remoteL1descInx = remoteL1descInx;
    L1desc[l1descInx].oprType = REMOTE_ZONE_OPR;
    L1desc[l1descInx].remoteZoneHost = remoteZoneHost;
    /* always repl the .dataObjInp */
    L1desc[l1descInx].dataObjInp = ( dataObjInp_t* )malloc( sizeof( dataObjInp_t ) );
    replDataObjInp( dataObjInp, L1desc[l1descInx].dataObjInp );
    L1desc[l1descInx].dataObjInpReplFlag = 1;
    dataObjInfo = L1desc[l1descInx].dataObjInfo =
                      ( dataObjInfo_t* )malloc( sizeof( dataObjInfo_t ) );
    bzero( dataObjInfo, sizeof( dataObjInfo_t ) );
    rstrcpy( dataObjInfo->objPath, dataObjInp->objPath, MAX_NAME_LEN );

    if ( openStat != NULL ) {
        dataObjInfo->dataSize = openStat->dataSize;
        rstrcpy( dataObjInfo->dataMode, openStat->dataMode, SHORT_STR_LEN );
        rstrcpy( dataObjInfo->dataType, openStat->dataType, NAME_LEN );
        L1desc[l1descInx].l3descInx = openStat->l3descInx;
        L1desc[l1descInx].replStatus = openStat->replStatus;
    }

    return l1descInx;
}
