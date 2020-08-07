#ifndef IRODS_FINALIZE_DATA_OBJECT_HPP
#define IRODS_FINALIZE_DATA_OBJECT_HPP

/// \file

#include "rcConnect.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: doxygen
int rc_finalize_data_object(rcComm_t* comm, const char* json_input, char** json_output);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // IRODS_FINALIZE_DATA_OBJECT_HPP

