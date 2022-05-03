#ifndef GET_RODS_ENV_H
#define GET_RODS_ENV_H

#include "irods/rodsDef.h"

typedef struct RodsEnvironment {
    char rodsUserName[NAME_LEN];
    char rodsHost[NAME_LEN];
    int  rodsPort;
    char rodsHome[MAX_NAME_LEN];
    char rodsCwd[MAX_NAME_LEN];
    char rodsAuthScheme[NAME_LEN];
    char rodsDefResource[NAME_LEN];
    char rodsZone[NAME_LEN];
    int rodsLogLevel;
    char rodsAuthFile[LONG_NAME_LEN];
    char rodsDebug[NAME_LEN];
    char rodsClientServerPolicy[ LONG_NAME_LEN ];
    char rodsClientServerNegotiation[ LONG_NAME_LEN ];

    // =-=-=-=-=-=-=-
    // client side options for encryption
    int  rodsEncryptionKeySize;
    int  rodsEncryptionSaltSize;
    int  rodsEncryptionNumHashRounds;
    char rodsEncryptionAlgorithm[ HEADER_TYPE_LEN ];

    // =-=-=-=-=-=-=-
    // client side options for hashing
    char rodsDefaultHashScheme[ NAME_LEN ];
    char rodsMatchHashPolicy[ NAME_LEN ];

    // =-=-=-=-=-=-=-
    // legacy ssl environment variables
    char irodsSSLCACertificatePath[MAX_NAME_LEN];
    char irodsSSLCACertificateFile[MAX_NAME_LEN];
    char irodsSSLVerifyServer[MAX_NAME_LEN];
    char irodsSSLCertificateChainFile[MAX_NAME_LEN];
    char irodsSSLCertificateKeyFile[MAX_NAME_LEN];
    char irodsSSLDHParamsFile[MAX_NAME_LEN];

    // =-=-=-=-=-=-=-
    // control plane parameters
    char irodsCtrlPlaneKey[MAX_NAME_LEN];
    int  irodsCtrlPlanePort;
    int  irodsCtrlPlaneEncryptionNumHashRounds;
    char irodsCtrlPlaneEncryptionAlgorithm[ HEADER_TYPE_LEN ];

    // =-=-=-=-=-=-=-
    // advanced settings
    int irodsMaxSizeForSingleBuffer;
    int irodsDefaultNumberTransferThreads;
    int irodsTransBufferSizeForParaTrans;
    int irodsConnectionPoolRefreshTime;

    // =-=-=-=-=-=-=-
    // override of plugin installation directory
    char irodsPluginHome[MAX_NAME_LEN];
} rodsEnv;

#ifdef __cplusplus
extern "C" {
#endif

int getRodsEnv( rodsEnv *myRodsEnv );

char *getRodsEnvFileName();
char *getRodsEnvAuthFileName();

int printRodsEnv( FILE* );

#ifdef __cplusplus

void _getRodsEnv( rodsEnv &myRodsEnv );
void _reloadRodsEnv( rodsEnv &myRodsEnv );

int getRodsEnvFromFile(rodsEnv& _env);
int getRodsEnvFromEnv(rodsEnv& _env);
int createRodsEnvDefaults(rodsEnv& _env);

/// \brief Populate \p _env with data from various sources for an iRODS client environment.
///
/// \param[out] _env \p RodsEnvironment that holds the client environment information.
/// \param[in] _always_return_valid_env Use default values if none are found.
///
/// \retval 0 on success
/// \retval non-zero on failure
///
/// \since 4.3.0
int get_irods_environment_from_file(rodsEnv& _env, bool _always_return_valid_env);

}
#endif // #ifdef __cplusplus
#endif // GET_RODS_ENV_H
