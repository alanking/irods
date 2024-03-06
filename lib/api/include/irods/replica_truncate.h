#ifndef IRODS_REPLICA_TRUNCATE_H
#define IRODS_REPLICA_TRUNCATE_H

struct RcComm;
struct DataObjInp;

#ifdef __cplusplus
extern "C" {
#endif

/// Truncate a replica for the specified data object to the specified size.
///
/// \parblock
/// This API selects a replica to truncate according to the rules of POSIX truncate(2). The caller may provide keywords
/// via condInput in order to influence the hierarchy resolution for selecting a replica to truncate.
/// \endparblock
///
/// \param[in] _comm A pointer to a RcComm.
/// \param[in] _inp \parblock
/// DataObjInp structure which requires the following inputs:
///     objPath - The full logical path to the target data object.
///     dataSize - The desired size of the replica after truncating.
///
/// The condInput supports the following keywords for hierarchy resolution for a "write" operation:
///     replNum - The replica number of the replica to truncate.
///     rescName - The name of the resource with the replica to truncate. Must be a root resource.
///     defRescName - The default resource to target in the absence of any other inputs or policy.
///     resc_hier - Full resource hierarchy to the replica to truncate. Use with caution.
///     irodsAdmin - Flag indicating that the operation is to be performed with elevated privileges. No value required.
/// \endparblock
/// \param[out] _out \parblock
/// Character string representing a JSON structure with the following form:
/// \code{.js}
/// {
///     // Resource hierarchy of the selected replica for truncate.
///     "resource_hierarchy": <string>,
///     // Replica number of the selected replica for truncate.
///     "replica_number": <integer>,
///     // A string containing any relevant message the client may wish to send to the user (including error messages).
///     "message": <string>
/// }
/// \endcode
/// \endparblock
///
/// \usage \parblock
/// \code{c}
///     RcComm* comm = NULL;
///     // Establish connection with iRODS server, authenticate, etc.
///
///     // Don't forget to call clearKeyVal on truncate_doi.condInput before exiting to prevent leaks.
///     DataObjInp truncate_doi;
///     memset(&truncate_doi, 0, sizeof(DataObjInp));
///
///     // Set the path and the desired size.
///     strncpy(truncate_doi.objPath, "/tempZone/home/alice/foo", MAX_NAME_LEN);
///     truncate_doi.size = 0;
///
///     // Target a specific replica, if desired.
///     addKeyVal(&truncate_doi.condInput, "replNum", "3");
///
///     // Need a character string to hold the output. Don't forget to free this before exiting to prevent leaks.
///     char* output_string = NULL;
///
///     const int ec = rc_replica_truncate(comm, &truncate_doi, &output_string);
///     if (ec < 0) {
///         // Error handling. Perhaps use the "message" field inside the output_string.
///     }
/// \endcode
/// \endparblock
///
/// \return An integer representing an iRODS error code, or 0.
/// \retval 0 on success.
/// \retval <0 on failure; an iRODS error code.
///
/// \since 4.3.2
int rc_replica_truncate(RcComm* _comm, DataObjInp* _inp, char** _out);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_REPLICA_TRUNCATE_H
