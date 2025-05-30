#include "irods/rcMisc.h"
#include "irods/rodsConnect.h"
#include "irods/rsGlobalExtern.hpp"
#include "irods/rcGlobalExtern.h"
#include "irods/miscServerFunct.hpp"
#include "irods/getRemoteZoneResc.h"
#include "irods/irods_resource_backport.hpp"
#include "irods/irods_logger.hpp"

#include <cstring>
#include <vector>
#include <iterator>
#include <experimental/iterator>
#include <sstream>

/* getAndConnRcatHost - get the rcat enabled host (result given in
 * rodsServerHost) based on the rcatZoneHint.
 * rcatZoneHint is the hint for which zone to go it. It can be :
 *      a full path - e.g., /A/B/C. In this case, "A" will be taken as the zone
 *      a zone name - a string with the first character that is no '/' is taken
 *         as a zone name.
 *      NULL string - default to local zone
 * If the rcat host is remote, it will automatically connect to the rcat host.
 */

int getAndConnRcatHost(
    rsComm_t *rsComm,
    int rcatType,
    const char *rcatZoneHint,
    rodsServerHost_t **rodsServerHost ) {

    int status = getRcatHost( rcatType, rcatZoneHint, rodsServerHost );

    if ( status < 0 ) {
        rodsLog( LOG_NOTICE,
                 "getAndConnRcatHost:getRcatHost() failed. error=%d", status );
        return status;
    }

    if ( ( *rodsServerHost )->localFlag == LOCAL_HOST ) {
        return LOCAL_HOST;
    }
    status = svrToSvrConnect( rsComm, *rodsServerHost );

    if ( status < 0 ) {
        rodsLog( LOG_NOTICE,
                 "getAndConnRcatHost: svrToSvrConnect to %s failed",
                 ( *rodsServerHost )->hostName->name );
        if ( ( *rodsServerHost )->rcatEnabled == REMOTE_ICAT ) {
            status = convZoneSockError( status );
        }
    }
    if ( status >= 0 ) {
        return REMOTE_HOST;
    }
    else {
        return status;
    }
}

int
getAndConnRcatHostNoLogin( rsComm_t *rsComm, int rcatType, char *rcatZoneHint,
                           rodsServerHost_t **rodsServerHost ) {
    int status = getRcatHost( rcatType, rcatZoneHint, rodsServerHost );

    if ( status < 0 ) {
        return status;
    }

    if ( ( *rodsServerHost )->localFlag == LOCAL_HOST ) {
        return LOCAL_HOST;
    }

    status = svrToSvrConnectNoLogin( rsComm, *rodsServerHost );

    if ( status < 0 ) {
        rodsLog( LOG_NOTICE,
                 "getAndConnRcatHost: svrToSvrConnectNoLogin to %s failed",
                 ( *rodsServerHost )->hostName->name );
        if ( ( *rodsServerHost )->rcatEnabled == REMOTE_ICAT ) {
            status = convZoneSockError( status );
        }
    }
    return status;
}

int
getRcatHost( int rcatType, const char *rcatZoneHint,
             rodsServerHost_t **rodsServerHost ) {
    int status;
    zoneInfo_t *myZoneInfo = NULL;

    status = getZoneInfo( rcatZoneHint, &myZoneInfo );
    if ( status < 0 ) {
        return status;
    }

    if (rcatType == PRIMARY_RCAT || myZoneInfo->secondaryServerHost == NULL) {
        *rodsServerHost = myZoneInfo->primaryServerHost;
        return myZoneInfo->primaryServerHost->localFlag;
    }
    else {
        *rodsServerHost = myZoneInfo->secondaryServerHost;
        return myZoneInfo->secondaryServerHost->localFlag;
    }
}

rodsServerHost_t*
mkServerHost(char *myHostAddr, char *zoneName) {
    if (NULL == myHostAddr || NULL == zoneName) {
        irods::log(ERROR(SYS_INTERNAL_NULL_INPUT_ERR, "bad params."));
        return NULL;
    }

    rodsServerHost_t* tmpRodsServerHost{(rodsServerHost_t*)malloc(sizeof(rodsServerHost_t))};
    memset(tmpRodsServerHost, 0, sizeof(rodsServerHost_t));

    /* XXXXX need to lookup the zone table when available */
    int status{queueHostName(tmpRodsServerHost, myHostAddr, 0)};
    if (status < 0) {
        irods::log(ERROR(status, "queueHostName failed"));
        free(tmpRodsServerHost);
        return NULL;
    }

    tmpRodsServerHost->localFlag = UNKNOWN_HOST_LOC;

    status = queueAddr(tmpRodsServerHost, myHostAddr);
    if (status < 0) {
        irods::log(ERROR(status, "queueAddr failed"));
        free( tmpRodsServerHost );
        return NULL;
    }
    status = matchHostConfig(tmpRodsServerHost);
    if (status < 0) {
        irods::log(ERROR(status, "matchHostConfig failed"));
        free( tmpRodsServerHost );
        return NULL;
    }
    status = getZoneInfo(zoneName, (zoneInfo_t**)(static_cast<void*>(&tmpRodsServerHost->zoneInfo)));
    if(status < 0) {
        irods::log(ERROR(status, "getZoneInfo failed"));
        free( tmpRodsServerHost );
        return NULL;
    }
    return tmpRodsServerHost;
}

int queueAddr(rodsServerHost_t* rodsServerHost, const char* myHostName)
{
    if ( rodsServerHost == NULL || myHostName == NULL ) {
        return 0;
    }

    // JMC :: consider empty host for coordinating nodes
    if ( irods::EMPTY_RESC_HOST != myHostName ) {
        time_t beforeTime = time( 0 );
        char canonicalName[260]; // DNS specification limits hostnames to 255-ish bytes
        const int ret_get_canonical_name = get_canonical_name(myHostName, canonicalName, sizeof(canonicalName));
        if (ret_get_canonical_name != 0) {
            if ( ProcessType == SERVER_PT ) {
                rodsLog( LOG_ERROR,
                         "queueAddr: get_canonical_name error for [%s], status [%d]",
                         myHostName, ret_get_canonical_name);
            }
            return SYS_GET_HOSTNAME_ERR;
        }
        time_t afterTime = time( 0 );
        if ( afterTime - beforeTime >= 2 ) {
            rodsLog( LOG_WARNING,
                     "get_canonical_name of %s is taking %d seconds. This could severely affect the interactivity of your iRODS system.",
                     myHostName, afterTime - beforeTime );
            /* XXXXXX may want to mark resource down later */
        }
        if ( strcasecmp( myHostName, canonicalName ) != 0 ) {
            queueHostName( rodsServerHost, canonicalName, 0 );
        }
    }

    return 0;
}

int
queueHostName( rodsServerHost_t *rodsServerHost, const char *myName, int topFlag ) {
    hostName_t *myHostName, *lastHostName;
    hostName_t *tmpHostName;

    myHostName = lastHostName = rodsServerHost->hostName;

    while ( myHostName != NULL ) {
        if ( strcmp( myName, myHostName->name ) == 0 ) {
            return 0;
        }
        lastHostName = myHostName;
        myHostName = myHostName->next;
    }

    tmpHostName = ( hostName_t* )malloc( sizeof( hostName_t ) );
    tmpHostName->name = strdup( myName );

    if ( topFlag > 0 ) {
        tmpHostName->next = rodsServerHost->hostName;
        rodsServerHost->hostName = tmpHostName;
    }
    else {
        if ( lastHostName == NULL ) {
            rodsServerHost->hostName = tmpHostName;
        }
        else {
            lastHostName->next = tmpHostName;
        }
        tmpHostName->next = NULL;
    }

    return 0;
}

int
queueRodsServerHost( rodsServerHost_t **rodsServerHostHead,
                   rodsServerHost_t *myRodsServerHost ) {
    rodsServerHost_t *lastRodsServerHost, *tmpRodsServerHost;

    lastRodsServerHost = tmpRodsServerHost = *rodsServerHostHead;
    while ( tmpRodsServerHost != NULL ) {
        lastRodsServerHost = tmpRodsServerHost;
        tmpRodsServerHost = tmpRodsServerHost->next;
    }

    if ( lastRodsServerHost == NULL ) {
        *rodsServerHostHead = myRodsServerHost;
    }
    else {
        lastRodsServerHost->next = myRodsServerHost;
    }
    myRodsServerHost->next = NULL;

    return 0;
}

int queueZone(const char* zoneName,
              int portNum,
              rodsServerHost_t* primaryServerHost,
              rodsServerHost_t* secondaryServerHost)
{
    bool zoneAlreadyInList = false;

    zoneInfo_t *tmpZoneInfo, *lastZoneInfo;
    zoneInfo_t *myZoneInfo;

    myZoneInfo = ( zoneInfo_t * ) malloc( sizeof( zoneInfo_t ) );

    memset( myZoneInfo, 0, sizeof( zoneInfo_t ) );

    rstrcpy( myZoneInfo->zoneName, zoneName, NAME_LEN );
    if (primaryServerHost != NULL) {
        myZoneInfo->primaryServerHost = primaryServerHost;
        primaryServerHost->zoneInfo = myZoneInfo;
    }
    if (secondaryServerHost != NULL) {
        myZoneInfo->secondaryServerHost = secondaryServerHost;
        secondaryServerHost->zoneInfo = myZoneInfo;
    }

    if ( portNum <= 0 ) {
        if ( ZoneInfoHead != NULL ) {
            myZoneInfo->portNum = ZoneInfoHead->portNum;
        }
        else {
            rodsLog( LOG_ERROR,
                     "queueZone:  Bad input portNum %d for %s", portNum, zoneName );
            free( myZoneInfo );
            return SYS_INVALID_SERVER_HOST;
        }
    }
    else {
        myZoneInfo->portNum = portNum;
    }

    /* queue it */

    lastZoneInfo = tmpZoneInfo = ZoneInfoHead;
    while ( tmpZoneInfo != NULL ) {
        if (strcmp(tmpZoneInfo->zoneName, myZoneInfo->zoneName) == 0 ) {
            zoneAlreadyInList = true;
        }
        lastZoneInfo = tmpZoneInfo;
        tmpZoneInfo = tmpZoneInfo->next;
    }

    if ( lastZoneInfo == NULL ) {
        ZoneInfoHead = myZoneInfo;
    } else if (!zoneAlreadyInList) {
        lastZoneInfo->next = myZoneInfo;
    }
    myZoneInfo->next = NULL;

    if (primaryServerHost == NULL) {
        rodsLog(LOG_DEBUG, "queueZone:  primaryServerHost for %s is NULL", zoneName);
        return SYS_INVALID_SERVER_HOST;
    }

    return 0;
}

int
matchHostConfig( rodsServerHost_t *myRodsServerHost ) {
    rodsServerHost_t *tmpRodsServerHost;
    int status;

    if ( myRodsServerHost == NULL ) {
        return 0;
    }

    if ( myRodsServerHost->localFlag == LOCAL_HOST ) {
        tmpRodsServerHost = HostConfigHead;
        while ( tmpRodsServerHost != NULL ) {
            if ( tmpRodsServerHost->localFlag == LOCAL_HOST ) {
                status = queueConfigName( tmpRodsServerHost, myRodsServerHost );
                return status;
            }
            tmpRodsServerHost = tmpRodsServerHost->next;
        }
    }
    else {
        tmpRodsServerHost = HostConfigHead;
        while ( tmpRodsServerHost != NULL ) {
            hostName_t *tmpHostName, *tmpConfigName;

            if ( tmpRodsServerHost->localFlag == LOCAL_HOST &&
                    myRodsServerHost->localFlag != UNKNOWN_HOST_LOC ) {
                tmpRodsServerHost = tmpRodsServerHost->next;
                continue;
            }

            tmpConfigName = tmpRodsServerHost->hostName;
            while ( tmpConfigName != NULL ) {
                tmpHostName = myRodsServerHost->hostName;
                while ( tmpHostName != NULL ) {
                    if ( strcmp( tmpHostName->name, tmpConfigName->name ) == 0 ) {
                        myRodsServerHost->localFlag = tmpRodsServerHost->localFlag;
                        queueConfigName( tmpRodsServerHost, myRodsServerHost );
                        return 0;
                    }
                    tmpHostName = tmpHostName->next;
                }
                tmpConfigName = tmpConfigName->next;
            }
            tmpRodsServerHost = tmpRodsServerHost->next;
        }
    }

    return 0;
}

int
queueConfigName( rodsServerHost_t *configServerHost,
               rodsServerHost_t *myRodsServerHost ) {
    hostName_t *tmpHostName = configServerHost->hostName;
    int cnt = 0;

    while ( tmpHostName != NULL ) {
        if ( cnt == 0 ) {
            /* queue the first one on top */
            queueHostName( myRodsServerHost, tmpHostName->name, 1 );
        }
        else {
            queueHostName( myRodsServerHost, tmpHostName->name, 0 );
        }
        cnt ++;
        tmpHostName = tmpHostName->next;
    }

    return 0;
}

int
resolveHost( rodsHostAddr_t *addr, rodsServerHost_t **rodsServerHost ) {
    rodsServerHost_t *tmpRodsServerHost = 0;
    char *myHostAddr = 0;
    char *myZoneName = 0;

    /* check if host exist */

    myHostAddr = addr->hostAddr;

    if ( strlen( myHostAddr ) == 0 ) {
        *rodsServerHost = ServerHostHead;
        return LOCAL_HOST;
    }
    if ( strlen( addr->zoneName ) == 0 ) {
        myZoneName = ZoneInfoHead->zoneName;
    }
    else {
        myZoneName = addr->zoneName;
    }

    tmpRodsServerHost = ServerHostHead;
    while ( tmpRodsServerHost != NULL ) {
        hostName_t *tmpName;
        zoneInfo_t *serverZoneInfo = ( zoneInfo_t * ) tmpRodsServerHost->zoneInfo;
        if ( strcmp( myZoneName, serverZoneInfo->zoneName ) == 0 ) {
            tmpName = tmpRodsServerHost->hostName;
            while ( tmpName != NULL ) {
                if ( strcasecmp( tmpName->name, myHostAddr ) == 0 ) {
                    *rodsServerHost = tmpRodsServerHost;
                    return tmpRodsServerHost->localFlag;
                }
                tmpName = tmpName->next;
            }
        }
        tmpRodsServerHost = tmpRodsServerHost->next;
    }

    /* no match */

    tmpRodsServerHost = mkServerHost( myHostAddr, myZoneName );

    if ( tmpRodsServerHost == NULL ) {
        rodsLog( LOG_ERROR,
                 "resolveHost: mkServerHost error" );
        return SYS_INVALID_SERVER_HOST;
    }

    /* assume it is remote */
    if ( tmpRodsServerHost->localFlag == UNKNOWN_HOST_LOC ) {
        tmpRodsServerHost->localFlag = REMOTE_HOST;
    }

    int status = queueRodsServerHost( &ServerHostHead, tmpRodsServerHost );
    if ( status < 0 ) {
        rodsLog( LOG_ERROR, "resolveHost - queueRodsServerHost failed." );
    }
    *rodsServerHost = tmpRodsServerHost;

    return tmpRodsServerHost->localFlag;
}

int
resoAndConnHostByDataObjInfo( rsComm_t *rsComm, dataObjInfo_t *dataObjInfo,
                              rodsServerHost_t **rodsServerHost ) {
    int status;
    rodsHostAddr_t addr;
    int remoteFlag;
    if ( dataObjInfo == NULL ) {
        rodsLog( LOG_NOTICE,
                 "resoAndConnHostByDataObjInfo: NULL dataObjInfo" );
        return SYS_INTERNAL_NULL_INPUT_ERR;
    }

    // =-=-=-=-=-=-=-
    // extract the host location from the resource hierarchy
    std::string location;
    irods::error ret = irods::get_loc_for_hier_string( dataObjInfo->rescHier, location );
    if ( !ret.ok() ) {
        irods::log( PASSMSG( "resoAndConnHostByDataObjInfo - failed in get_loc_for_hier_string", ret ) );
        return ret.code();
    }


    memset( &addr, 0, sizeof( addr ) );
    rstrcpy( addr.hostAddr, location.c_str(), NAME_LEN );

    remoteFlag = resolveHost( &addr, rodsServerHost );

    if ( remoteFlag == REMOTE_HOST ) {
        status = svrToSvrConnect( rsComm, *rodsServerHost );
        if ( status < 0 ) {
            rodsLog( LOG_ERROR,
                     "resAndConnHostByDataObjInfo: svrToSvrConnect to %s failed",
                     ( *rodsServerHost )->hostName->name );
        }
    }
    return remoteFlag;
}

int
printServerHost( rodsServerHost_t *myServerHost ) {
    namespace log = irods::experimental::log;

    std::vector<log::key_value> server_info;
    hostName_t *tmpHostName;
    std::string hostname_label;

    if ( myServerHost->localFlag == LOCAL_HOST ) {
        hostname_label = "local_hostname";
    }
    else {
        hostname_label = "remote_hostname";
    }

    tmpHostName = myServerHost->hostName;

    std::vector<std::string> hostnames;

    while ( tmpHostName != NULL ) {
        hostnames.emplace_back(tmpHostName->name);
        tmpHostName = tmpHostName->next;
    }

    std::stringstream ss;
    std::copy(std::cbegin(hostnames),
              std::cend(hostnames),
              std::experimental::make_ostream_joiner(ss, ", "));
    server_info.push_back({hostname_label, ss.str()});
    server_info.push_back({"port", std::to_string(static_cast<zoneInfo_t*>(myServerHost->zoneInfo)->portNum)});

    log::server::info(server_info);

    return 0;
}

int
printZoneInfo() {
    zoneInfo_t *tmpZoneInfo;
    rodsServerHost_t *tmpRodsServerHost;

    tmpZoneInfo = ZoneInfoHead;

    namespace log = irods::experimental::log;

    std::vector<log::key_value> zone_info;

    while ( tmpZoneInfo != NULL ) {
        /* print the primary */
        tmpRodsServerHost = (rodsServerHost_t*) tmpZoneInfo->primaryServerHost;

        zone_info.push_back({"zone_info.name", tmpZoneInfo->zoneName});

        if ( tmpRodsServerHost->rcatEnabled == LOCAL_ICAT ) {
            zone_info.push_back({"zone_info.type", "LOCAL_ICAT"});
        }
        else {
            zone_info.push_back({"zone_info.type", "REMOTE_ICAT"});
        }

        zone_info.push_back({"zone_info.host", tmpRodsServerHost->hostName->name});
        zone_info.push_back({"zone_info.port", std::to_string(tmpZoneInfo->portNum)});

        /* print the secondary */
        tmpRodsServerHost = (rodsServerHost_t*) tmpZoneInfo->secondaryServerHost;
        if ( tmpRodsServerHost != NULL ) {
            zone_info.push_back({"zone_info.secondary_zone_name", tmpZoneInfo->zoneName});
            zone_info.push_back({"zone_info.secondary_type", "LOCAL_SECONDARY_ICAT"});
            zone_info.push_back({"zone_info.secondary_host", tmpRodsServerHost->hostName->name});
            zone_info.push_back({"zone_info.secondary_port", std::to_string(tmpZoneInfo->portNum)});
        }

        log::server::info(zone_info);
        zone_info.clear();

        tmpZoneInfo = tmpZoneInfo->next;
    }

    return 0;
}

int
convZoneSockError( int inStatus ) {
    int unixErr = getErrno( inStatus );
    if ( inStatus + unixErr == USER_SOCK_CONNECT_ERR ) {
        return CROSS_ZONE_SOCK_CONNECT_ERR - unixErr;
    }
    else {
        return inStatus;
    }
}

int
getZoneInfo( const char *rcatZoneHint, zoneInfo_t **myZoneInfo ) {
    int status;
    zoneInfo_t *tmpZoneInfo;
    int zoneInput;
    char zoneName[NAME_LEN];

    if ( rcatZoneHint == NULL || strlen( rcatZoneHint ) == 0 ) {
        zoneInput = 0;
    }
    else {
        zoneInput = 1;
        getZoneNameFromHint( rcatZoneHint, zoneName, NAME_LEN );
    }

    *myZoneInfo = NULL;
    tmpZoneInfo = ZoneInfoHead;
    while ( tmpZoneInfo != NULL ) {
        if ( zoneInput == 0 ) { /* assume local */
            if (tmpZoneInfo->primaryServerHost->rcatEnabled == LOCAL_ICAT) {
                *myZoneInfo = tmpZoneInfo;
            }
        }
        else {          /* remote zone */
            if ( strcmp( zoneName, tmpZoneInfo->zoneName ) == 0 ) {
                *myZoneInfo = tmpZoneInfo;
            }
        }
        if ( *myZoneInfo != NULL ) {
            return 0;
        }
        tmpZoneInfo = tmpZoneInfo->next;
    }

    if ( zoneInput == 0 ) {
        rodsLog( LOG_ERROR,
                 "getRcatHost: No local Rcat" );
        return SYS_INVALID_ZONE_NAME;
    }
    else {
        rodsLog( LOG_DEBUG,
                 "getZoneInfo: Invalid zone name from hint %s", rcatZoneHint );
        status = getZoneInfo( ( const char* )NULL, myZoneInfo );
        if ( status < 0 ) {
            return SYS_INVALID_ZONE_NAME;
        }
        else {
            return 0;
        }
    }
}

int
getLocalZoneInfo( zoneInfo_t **outZoneInfo ) {
    zoneInfo_t *tmpZoneInfo;

    tmpZoneInfo = ZoneInfoHead;
    while ( tmpZoneInfo != NULL ) {
        if (tmpZoneInfo->primaryServerHost->rcatEnabled == LOCAL_ICAT) {
            *outZoneInfo = tmpZoneInfo;
            return 0;
        }
        tmpZoneInfo = tmpZoneInfo->next;
    }
    rodsLog( LOG_ERROR,
             "getLocalZoneInfo: Local Zone does not exist" );

    *outZoneInfo = NULL;
    return SYS_INVALID_ZONE_NAME;
}

char*
getLocalZoneName() {
    zoneInfo_t *tmpZoneInfo;

    if ( getLocalZoneInfo( &tmpZoneInfo ) >= 0 ) {
        return tmpZoneInfo->zoneName;
    }
    else {
        return NULL;
    }
}

/* Check if there is a connected ICAT host, and if there is, disconnect */
int
getAndDisconnRcatHost( int rcatType, char *rcatZoneHint,
                       rodsServerHost_t **rodsServerHost ) {
    int status;

    status = getRcatHost( rcatType, rcatZoneHint, rodsServerHost );

    if ( status < 0 ) {
        return status;
    }

    if ( ( *rodsServerHost )->conn != NULL ) { /* a connection exists */
        status = rcDisconnect( ( *rodsServerHost )->conn );
        return status;
    }
    return 0;
}

int
disconnRcatHost( int rcatType, const char *rcatZoneHint ) {
    int status;
    rodsServerHost_t *rodsServerHost = NULL;

    status = getRcatHost( rcatType, rcatZoneHint, &rodsServerHost );

    if ( status < 0 || NULL == rodsServerHost ) { // JMC cppcheck - nullptr
        return status;
    }

    if ( ( rodsServerHost )->localFlag == LOCAL_HOST ) {
        return LOCAL_HOST;
    }

    if ( rodsServerHost->conn != NULL ) { /* a connection exists */
        status = rcDisconnect( rodsServerHost->conn );
        rodsServerHost->conn = NULL;
    }
    if ( status >= 0 ) {
        return REMOTE_HOST;
    }
    else {
        return status;
    }
}

/* resetRcatHost is similar to disconnRcatHost except it does not disconnect */

int
resetRcatHost( int rcatType, const char *rcatZoneHint ) {
    rodsServerHost_t *rodsServerHost = NULL;
    int status = getRcatHost( rcatType, rcatZoneHint, &rodsServerHost );

    if ( status < 0 || NULL == rodsServerHost ) { // JMC cppcheck - nullptr
        return status;
    }

    if ( rodsServerHost->localFlag == LOCAL_HOST ) {
        return LOCAL_HOST;
    }

    rodsServerHost->conn = NULL;
    return REMOTE_HOST;
}

int
disconnectAllSvrToSvrConn() {
    rodsServerHost_t *tmpRodsServerHost;

    /* check if host exist */

    tmpRodsServerHost = ServerHostHead;
    while ( tmpRodsServerHost != NULL ) {
        if ( tmpRodsServerHost->conn != NULL ) {
            rcDisconnect( tmpRodsServerHost->conn );
            tmpRodsServerHost->conn = NULL;
        }
        tmpRodsServerHost = tmpRodsServerHost->next;
    }
    return 0;
}

/* getAndConnRemoteZone - get the remote zone host (result given in
 * rodsServerHost) based on the dataObjInp->objPath as zoneHint.
 * If the host is a remote zone, automatically connect to the host.
 */

int
getAndConnRemoteZone( rsComm_t *rsComm, dataObjInp_t *dataObjInp,
                      rodsServerHost_t **rodsServerHost, char *remoteZoneOpr ) {
    int status;

    status = getRemoteZoneHost( rsComm, dataObjInp, rodsServerHost,
                                remoteZoneOpr );

    if ( status == LOCAL_HOST ) {
        return LOCAL_HOST;
    }
    else if ( status < 0 ) {
        return status;
    }

    status = svrToSvrConnect( rsComm, *rodsServerHost );

    if ( status < 0 ) {
        rodsLog( LOG_ERROR,
                 "getAndConnRemoteZone: svrToSvrConnect to %s failed",
                 ( *rodsServerHost )->hostName->name );
    }
    if ( status >= 0 ) {
        return REMOTE_HOST;
    }
    else {
        return status;
    }
}

int
isLocalZone(const char *zoneHint ) {
    int status;
    rodsServerHost_t *icatServerHost = NULL;

    status = getRcatHost(PRIMARY_RCAT, zoneHint, &icatServerHost);

    if ( status < 0 || NULL == icatServerHost ) { // JMC cppcheck - nullptr
        return 0;
    }

    if ( icatServerHost->rcatEnabled != REMOTE_ICAT ) {
        /* local zone. */
        return 1;
    }
    else {
        return 0;
    }
}

/* isSameZone - return 1 if from same zone, otherwise return 0
 */
int
isSameZone( char *zoneHint1, char *zoneHint2 ) {
    char zoneName1[NAME_LEN], zoneName2[NAME_LEN];

    if ( zoneHint1 == NULL || zoneHint2 == NULL ) {
        return 0;
    }

    getZoneNameFromHint( zoneHint1, zoneName1, NAME_LEN );
    getZoneNameFromHint( zoneHint2, zoneName2, NAME_LEN );

    if ( strcmp( zoneName1, zoneName2 ) == 0 ) {
        return 1;
    }
    else {
        return 0;
    }
}

int
getRemoteZoneHost( rsComm_t *rsComm, dataObjInp_t *dataObjInp,
                   rodsServerHost_t **rodsServerHost, char *remoteZoneOpr ) {
    int status;
    rodsServerHost_t *icatServerHost = NULL;
    rodsHostAddr_t *rescAddr = NULL;

    status = getRcatHost(PRIMARY_RCAT, dataObjInp->objPath, &icatServerHost);

    if ( status < 0 || NULL == icatServerHost ) { // JMC cppcheck - nullptr
        return status;
    }

    if ( icatServerHost->rcatEnabled != REMOTE_ICAT ) {
        /* local zone. nothing to do */
        return LOCAL_HOST;
    }

    status = svrToSvrConnect( rsComm, icatServerHost );

    if ( status < 0 ) {
        rodsLog( LOG_ERROR,
                 "getRemoteZoneHost: svrToSvrConnect to %s failed, status = %d",
                 icatServerHost->hostName->name, status );
        status = convZoneSockError( status );
        return status;
    }

    addKeyVal( &dataObjInp->condInput, REMOTE_ZONE_OPR_KW, remoteZoneOpr );

    status = rcGetRemoteZoneResc( icatServerHost->conn, dataObjInp, &rescAddr );
    if ( status < 0 ) {
        rodsLog( LOG_ERROR,
                 "getRemoteZoneHost: rcGetRemoteZoneResc for %s failed, status = %d",
                 dataObjInp->objPath, status );
        return status;
    }

    status = resolveHost( rescAddr, rodsServerHost );

    free( rescAddr );

    return status;
}

int
isLocalHost( const char *hostAddr ) {
    int remoteFlag;
    rodsServerHost_t *rodsServerHost;
    rodsHostAddr_t addr;

    std::memset(&addr, 0, sizeof(addr));
    rstrcpy( addr.hostAddr, hostAddr, NAME_LEN );
    remoteFlag = resolveHost( &addr, &rodsServerHost );
    if ( remoteFlag == LOCAL_HOST ) {
        return 1;
    }

    return 0;
}

int
getReHost( rodsServerHost_t **rodsServerHost ) {
    int status;

    rodsServerHost_t *tmpRodsServerHost;

    tmpRodsServerHost = ServerHostHead;
    while ( tmpRodsServerHost != NULL ) {
        if ( tmpRodsServerHost->reHostFlag == 1 ) {
            *rodsServerHost = tmpRodsServerHost;
            return 0;
        }
        tmpRodsServerHost = tmpRodsServerHost->next;
    }
    status = getRcatHost(PRIMARY_RCAT, (const char*) NULL, rodsServerHost);

    return status;
}

/* getAndConnReHost - Get the irodsDelayServer host (result given in
 * rodsServerHost).
 * If the is remote, it will automatically connect to the server where
 * irodsDelayServer is run.
 */

int
getAndConnReHost( rsComm_t *rsComm, rodsServerHost_t **rodsServerHost ) {
    int status;

    status = getReHost( rodsServerHost );

    if ( status < 0 ) {
        rodsLog( LOG_NOTICE,
                 "getAndConnReHost:getReHost() failed. error=%d", status );
        return status;
    }

    if ( ( *rodsServerHost )->localFlag == LOCAL_HOST ) {
        return LOCAL_HOST;
    }

    status = svrToSvrConnect( rsComm, *rodsServerHost );

    if ( status < 0 ) {
        rodsLog( LOG_NOTICE,
                 "getAndConnReHost: svrToSvrConnect to %s failed",
                 ( *rodsServerHost )->hostName->name );
    }
    if ( status >= 0 ) {
        return REMOTE_HOST;
    }
    else {
        return status;
    }
}
