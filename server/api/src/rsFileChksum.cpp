#include "fileChksum.h"
#include "miscServerFunct.hpp"
#include "rsFileChksum.hpp"
#include "irods_log.hpp"
#include "irods_file_object.hpp"
#include "irods_stacktrace.hpp"
#include "irods_resource_backport.hpp"
#include "irods_hasher_factory.hpp"
#include "irods_server_properties.hpp"
#include "MD5Strategy.hpp"
#include "irods_hierarchy_parser.hpp"
#include "dstream.hpp"

#define IRODS_IO_TRANSPORT_ENABLE_SERVER_SIDE_API
#include "transport/default_transport.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "replica.hpp"

#include <algorithm>

#define SVR_MD5_BUF_SZ (1024*1024)

int rsFileChksum(rsComm_t* rsComm, fileChksumInp_t* fileChksumInp, char** chksumStr)
{
    rodsServerHost_t* rodsServerHost;
    int remoteFlag;
    irods::error ret = irods::get_host_for_hier_string(fileChksumInp->rescHier, remoteFlag, rodsServerHost);
    if (!ret.ok()) {
        irods::log(PASSMSG("failed in call to irods::get_host_for_hier_string", ret));
        return -1;
    }

    if (LOCAL_HOST == remoteFlag) {
        return _rsFileChksum(rsComm, fileChksumInp, chksumStr);
    }

    if (REMOTE_HOST == remoteFlag) {
        return remoteFileChksum(rsComm, fileChksumInp, chksumStr, rodsServerHost);
    }

    if (remoteFlag < 0) {
        return remoteFlag;
    }

    rodsLog(LOG_NOTICE, "rsFileChksum: resolveHost returned unrecognized value %d", remoteFlag);

    return SYS_UNRECOGNIZED_REMOTE_FLAG;
}

int remoteFileChksum(rsComm_t* rsComm,
                     fileChksumInp_t* fileChksumInp,
                     char** chksumStr,
                     rodsServerHost_t* rodsServerHost)
{
    if (!rodsServerHost) {
        rodsLog(LOG_NOTICE, "remoteFileChksum: Invalid rodsServerHost");
        return SYS_INVALID_SERVER_HOST;
    }

    if (const auto ec = svrToSvrConnect(rsComm, rodsServerHost); ec < 0) {
        return ec;
    }

    const auto status = rcFileChksum(rodsServerHost->conn, fileChksumInp, chksumStr);

    if (status < 0) {
        rodsLog(LOG_NOTICE,
                "remoteFileChksum: rcFileChksum failed for %s",
                fileChksumInp->fileName);
    }

    return status;
}

int _rsFileChksum(rsComm_t* rsComm, fileChksumInp_t* fileChksumInp, char** chksumStr)
{
    int status;
    if ( !*chksumStr ) {
        *chksumStr = ( char* )malloc( sizeof( char ) * NAME_LEN );
    }

    status = fileChksum(
                 rsComm,
                 fileChksumInp->objPath,
                 fileChksumInp->fileName,
                 fileChksumInp->rescHier,
                 fileChksumInp->orig_chksum,
                 *chksumStr );
    if ( status < 0 ) {
        rodsLog( LOG_DEBUG,
                 "_rsFileChksum: fileChksum for %s, status = %d",
                 fileChksumInp->fileName, status );
        free( *chksumStr );
        *chksumStr = NULL;
    }

    return status;
}

int fileChksum(rsComm_t* rsComm,
               char* objPath,
               char* fileName,
               char* rescHier,
               char* orig_chksum,
               char* chksumStr)
{
    // =-=-=-=-=-=-=-
    // capture server hashing settings
    std::string hash_scheme( irods::MD5_NAME );
    try {
        hash_scheme = irods::get_server_property<const std::string>(irods::CFG_DEFAULT_HASH_SCHEME_KW);
    } catch ( const irods::exception& ) {}

    // make sure the read parameter is lowercased
    std::transform(
        hash_scheme.begin(),
        hash_scheme.end(),
        hash_scheme.begin(),
        ::tolower );

    std::string hash_policy;
    try {
        hash_policy = irods::get_server_property<const std::string>(irods::CFG_MATCH_HASH_POLICY_KW);
    } catch ( const irods::exception& ) {}

    // =-=-=-=-=-=-=-
    // extract scheme from checksum string
    std::string chkstr_scheme;
    if ( orig_chksum ) {
        irods::error ret = irods::get_hash_scheme_from_checksum(
                  orig_chksum,
                  chkstr_scheme );
        if ( !ret.ok() ) {
            //irods::log( PASS( ret ) );
        }
    }

    // =-=-=-=-=-=-=-
    // check the hash scheme against the policy
    // if necessary
    std::string final_scheme( hash_scheme );
    if ( !chkstr_scheme.empty() ) {
        if ( !hash_policy.empty() ) {
            if ( irods::STRICT_HASH_POLICY == hash_policy ) {
                if ( hash_scheme != chkstr_scheme ) {
                    return USER_HASH_TYPE_MISMATCH;
                }
            }
        }
        final_scheme = chkstr_scheme;
    }

    rodsLog(
        LOG_DEBUG,
        "fileChksum :: final_scheme [%s]  chkstr_scheme [%s]  hash_policy [%s]",
        final_scheme.c_str(),
        chkstr_scheme.c_str(),
        hash_policy.c_str() );

    // =-=-=-=-=-=-=-
    // create a hasher object and init given a scheme
    // if it is unsupported then default to md5
    irods::Hasher hasher;
    const auto ret = irods::getHasher( final_scheme, hasher );
    if ( !ret.ok() ) {
        irods::log( PASS( ret ) );
        irods::getHasher( irods::MD5_NAME, hasher );
    }

    irods::hierarchy_parser hp{rescHier};
    std::string leaf_resc;

    if (const auto err = hp.last_resc(leaf_resc); !err.ok()) {
        return err.code();
    }

    auto bytes_remaining = irods::experimental::replica::replica_size(*rsComm, objPath, leaf_resc);

    namespace io = irods::experimental::io;

    io::server::native_transport tp{*rsComm};
    io::idstream in{tp, objPath, io::leaf_resource_name{leaf_resc}};

    if (!in) {
        rodsLog(LOG_ERROR, "%s - Failed to open replica for reading [logical_path=%s, physical_path=%s]",
                __FUNCTION__, objPath, fileName);
        return UNIX_FILE_OPEN_ERR;
    }

    char buffer[SVR_MD5_BUF_SZ];

    while (in && bytes_remaining > 0) {
        in.read(buffer, std::min(bytes_remaining, sizeof(buffer)));

        if (in.gcount() > 0) {
            bytes_remaining -= in.gcount();
            hasher.update(std::string(buffer, in.gcount()));
        }
    }

    // =-=-=-=-=-=-=-
    // extract the digest from the hasher object
    // and copy to outgoing string
    std::string digest;
    hasher.digest(digest);
    strncpy(chksumStr, digest.c_str(), NAME_LEN);

    return 0;
}

