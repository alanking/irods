#ifndef RS_FINALIZE_DATA_OBJECT_HPP
#define RS_FINALIZE_DATA_OBJECT_HPP

/// \file

#include "rcConnect.h"
#include "rodsDef.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: doxygen
auto rs_finalize_data_object(rsComm_t* _comm, const char* _json_input, char** _json_output) -> int;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // #ifndef RS_FINALIZE_DATA_OBJECT_HPP

