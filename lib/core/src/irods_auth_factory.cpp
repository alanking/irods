// =-=-=-=-=-=-=-
#include "irods/irods_auth_factory.hpp"
#include "irods/irods_native_auth_object.hpp"
#include "irods/irods_pam_auth_object.hpp"
#include "irods/irods_generic_auth_object.hpp"
#include "irods/rodsErrorTable.h"
#include <boost/algorithm/string.hpp>

namespace irods {
/// =-=-=-=-=-=-=-
/// @brief super basic free factory function to create an auth object
///        given the requested authentication scheme
    error auth_factory(
        const std::string& _scheme,
        rError_t*          _r_error,
        auth_object_ptr&   _ptr ) {
        // ensure scheme is lower case for comparison
        std::string scheme = boost::algorithm::to_lower_copy( _scheme );

        if ( scheme.empty() || AUTH_NATIVE_SCHEME == scheme ) {
            _ptr.reset( new native_auth_object( _r_error ) );
        }
        else if ( AUTH_PAM_SCHEME == scheme ) {
            _ptr.reset( new pam_auth_object( _r_error ) );
        }
        else {
            _ptr.reset( new irods::generic_auth_object( scheme, _r_error ) );
        }

        return SUCCESS();

    } // auth_factory

}; // namespace irods



