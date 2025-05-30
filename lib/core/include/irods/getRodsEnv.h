#ifndef IRODS_GET_RODS_ENV_H
#define IRODS_GET_RODS_ENV_H

#include "irods/rodsDef.h"

// NOLINTNEXTLINE(modernize-use-using)
typedef struct RodsEnvironment {
    char rodsUserName[NAME_LEN];
    char rodsHost[LONG_NAME_LEN];
    int  rodsPort;
    char rodsHome[MAX_NAME_LEN];
    char rodsCwd[MAX_NAME_LEN];
    char rodsAuthScheme[NAME_LEN];
    char rodsDefResource[NAME_LEN];
    char rodsZone[NAME_LEN];
    int rodsLogLevel;
    char rodsAuthFile[LONG_NAME_LEN];
    char rodsClientServerPolicy[ LONG_NAME_LEN ];
    char rodsClientServerNegotiation[ LONG_NAME_LEN ];

    // client side options for encryption
    int  rodsEncryptionKeySize;
    int  rodsEncryptionSaltSize;
    int  rodsEncryptionNumHashRounds;
    char rodsEncryptionAlgorithm[ HEADER_TYPE_LEN ];

    // client side options for hashing
    char rodsDefaultHashScheme[ NAME_LEN ];
    char rodsMatchHashPolicy[ NAME_LEN ];

    // legacy ssl environment variables
    char irodsSSLCACertificatePath[MAX_NAME_LEN];
    char irodsSSLCACertificateFile[MAX_NAME_LEN];
    char irodsSSLVerifyServer[MAX_NAME_LEN];

    // advanced settings
    int irodsMaxSizeForSingleBuffer;
    int irodsDefaultNumberTransferThreads;
    int irodsTransBufferSizeForParaTrans;
    int irodsConnectionPoolRefreshTime;

    // override of plugin installation directory
    char irodsPluginDirectory[MAX_NAME_LEN];

    // TCP keepalive configurations
    int tcp_keepalive_intvl;
    int tcp_keepalive_probes;
    int tcp_keepalive_time;
} rodsEnv;

#ifdef __cplusplus
extern "C" {
#endif

int getRodsEnv( rodsEnv *myRodsEnv );

char *getRodsEnvFileName();
char *getRodsEnvAuthFileName();

int printRodsEnv( FILE* );

int capture_string_property(const char* _key, char* _val, size_t _val_size);

#ifdef __cplusplus

void _getRodsEnv( rodsEnv &myRodsEnv );
void _reloadRodsEnv( rodsEnv &myRodsEnv );

}
#endif

#endif // IRODS_GET_RODS_ENV_H
