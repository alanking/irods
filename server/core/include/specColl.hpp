#ifndef SPEC_COLL_HPP
#define SPEC_COLL_HPP

#include "rods.h"
#include "objInfo.h"
#include "dataObjInpOut.h"
#include "ruleExecSubmit.h"
#include "rcGlobalExtern.h"
#include "rsGlobalExtern.hpp"

extern "C" {

    int
    modCollInfo2( rsComm_t *rsComm, specColl_t *specColl, int clearFlag );
    int
    querySpecColl( rsComm_t *rsComm, char *objPath, genQueryOut_t **genQueryOut );
    int
    queueSpecCollCache( rsComm_t *rsComm, genQueryOut_t *genQueryOut, const char *objPath ); // JMC - backport 4680
    int
    queueSpecCollCacheWithObjStat( rodsObjStat_t *rodsObjStatOut );
    specCollCache_t *
    matchSpecCollCache(const char *objPath );
    int
    getSpecCollCache( rsComm_t *rsComm, char *objPath, int inCachOnly,
                      specCollCache_t **specCollCache );
    int
    statPathInSpecColl( rsComm_t *rsComm, char *objPath,
                        int inCachOnly, rodsObjStat_t **rodsObjStatOut );
    int
    specCollSubStat( rsComm_t *rsComm, specColl_t *specColl,
                     char *subPath, specCollPerm_t specCollPerm, dataObjInfo_t **dataObjInfo );
    int
    resolvePathInSpecColl( rsComm_t *rsComm, char *objPath,
                           specCollPerm_t specCollPerm, int inCachOnly, dataObjInfo_t **dataObjInfo );
    int
    resolveLinkedPath( rsComm_t *rsComm, char *objPath,
                       specCollCache_t **specCollCache, keyValPair_t *condInput );

}

namespace irods
{
    auto get_special_collection_type_for_data_object(RsComm& _comm, DataObjInp& _inp) -> int;

    auto data_object_create_in_special_collection(RsComm* rsComm, DataObjInp& dataObjInp) -> int;

    auto create_sub_struct_file(RsComm *rsComm, const int l1descInx) -> int;
} // namespace irods

#endif	// SPEC_COLL_HPP
