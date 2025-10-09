#include <string>

/// \file

namespace irods::authentication
{
    /// \returns A \p std::string which can be used as a session token for authenticating with iRODS.
    ///
    /// \since 5.1.0
    auto generate_session_token() -> std::string;
} //namespace irods::authentication
