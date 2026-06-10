#ifndef IRODS_SERVER_CONNECTION_HPP
#define IRODS_SERVER_CONNECTION_HPP

/// \file

//#include "irods/fully_qualified_username.hpp"

#include <memory>

struct RsComm;

namespace irods
{
    class server_connection
    {
      public:
        server_connection();
#ifdef IRODS_SERVER_CONNECTION_ALLOW_COPY
        server_connection(const RsComm& comm);
#endif

        server_connection(server_connection&& other) = default;
        auto operator=(server_connection&& other) -> server_connection& = default;

        ~server_connection();

        operator RsComm&() const; // NOLINT(google-explicit-constructor)

        explicit operator RsComm*() const noexcept;

      private:
        auto initialize() -> void;

#ifdef IRODS_SERVER_CONNECTION_ALLOW_COPY
        auto copy(const RsComm& comm) -> void;
#endif

        std::unique_ptr<RsComm> conn_;
    }; // class server_connection
} // namespace irods

#endif // IRODS_CLIENT_CONNECTION_HPP
