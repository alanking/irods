#include "irods/authentication_server_utils.hpp"

#include <string>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace irods::authentication
{
    auto generate_session_token() -> std::string
    {
        std::string uuid;
        uuid.reserve(session_token_length);
        uuid = to_string(boost::uuids::random_generator{}());
        return uuid;
    } // generate_unique_key
} // namespace irods::authentication
