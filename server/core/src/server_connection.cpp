#include "irods/server_connection.hpp"

#include "irods/getRodsEnv.h"
#include "irods/irods_exception.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_server_properties.hpp"
#include "irods/rcMisc.h"
#include "irods/rodsErrorTable.h"
#include "irods/rodsVersion.h"

#include "irods/rcConnect.h"

#include <cstring>
#include <memory>

using log_server = irods::experimental::log::server;

namespace irods
{
    server_connection::server_connection()
        : conn_{nullptr}
    {
        conn_ = std::make_unique<RsComm>();
        initialize();
    } // default constructor

#ifdef IRODS_SERVER_CONNECTION_ALLOW_COPY
    server_connection::server_connection(const RsComm& comm)
        : conn_{nullptr}
    {
        conn_ = std::make_unique<RsComm>();
        copy(comm);
    } // default constructor
#endif

    server_connection::~server_connection()
    {
        // TODO: We should probably just have a function which frees RsComm stuff
        if (nullptr != conn_) {
            if (nullptr != conn_->portalOpr) {
                clearKeyVal(&conn_->portalOpr->dataOprInp.condInput);
                std::free(conn_->portalOpr);
                conn_->portalOpr = nullptr;
            }
            if (nullptr != conn_->reconnAddr) {
                std::free(conn_->reconnAddr);
                conn_->reconnAddr = nullptr;
            }
            if (nullptr != conn_->auth_scheme) {
                std::free(conn_->auth_scheme);
                conn_->auth_scheme = nullptr;
            }
            if (nullptr != conn_->ssl) {
                SSL_free(conn_->ssl);
                conn_->ssl = nullptr;
            }
            clearKeyVal(&conn_->session_props);
            // Do not freeRError because RsComm::rError is on the stack.
            freeRErrorContent(&conn_->rError);
        }
    } // destructor

    server_connection::operator RsComm&() const
    {
        if (!conn_) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
            THROW(SYS_LIBRARY_ERROR, "Invalid connection object");
        }

        return *conn_;
    } // operator RcComm&

    server_connection::operator RsComm*() const noexcept
    {
        return conn_.get();
    } // operator RcComm*

    // Because we are using the local environment, I guess we can just pull info from there?
    auto server_connection::initialize() -> void
    {
        auto& rsComm = *conn_;

        std::memset(&rsComm, 0, sizeof(rsComm));

        if (const auto env_ec = getRodsEnv(&rsComm.myEnv); env_ec < 0) {
            THROW(env_ec, fmt::format("{}: Error initializing environment for RsComm: {}", __func__, env_ec));
        }

        // Get user information for the "zone user".
        const auto config_handle = irods::server_properties::instance().map();
        const auto& config = config_handle.get_json();
        const auto& zone_name = config.at(irods::KW_CFG_ZONE_NAME).get_ref<const std::string&>();
        const auto& zone_user = config.at(irods::KW_CFG_ZONE_USER).get_ref<const std::string&>();

        std::strncpy(rsComm.proxyUser.userName, zone_user.c_str(), sizeof(rsComm.proxyUser.userName) - 1);
        std::strncpy(rsComm.clientUser.userName, zone_user.c_str(), sizeof(rsComm.clientUser.userName) - 1);
        std::strncpy(rsComm.proxyUser.rodsZone, zone_name.c_str(), sizeof(rsComm.proxyUser.rodsZone) - 1);
        std::strncpy(rsComm.clientUser.rodsZone, zone_name.c_str(), sizeof(rsComm.clientUser.rodsZone) - 1);

        /* always use NATIVE_PROT as a client. e.g., server to server comm */
        rsComm.irodsProt = NATIVE_PROT;
        std::strncpy(rsComm.cliVersion.relVersion, RODS_REL_VERSION, sizeof(rsComm.cliVersion.relVersion) - 1);
        std::strncpy(rsComm.cliVersion.apiVersion, RODS_API_VERSION, sizeof(rsComm.cliVersion.apiVersion) - 1);

        // TODO: Consider actually authenticating... For now, we're just an admin. That's it.
        rsComm.proxyUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
        rsComm.clientUser.authInfo.authFlag = LOCAL_PRIV_USER_AUTH;
    } // server_connection::initialize

#ifdef IRODS_SERVER_CONNECTION_ALLOW_COPY
    auto server_connection::copy(const RsComm& comm) -> void
    {
        // Copy everything.
        std::memcpy(conn_.get(), &comm, sizeof(comm));

        // Now check to see if any of the pointers are valid and do deep copies of those.
        if (nullptr != comm.portalOpr) {
            conn_->portalOpr = static_cast<PortalOpr*>(std::malloc(sizeof(PortalOpr)));
            std::memset(conn_->portalOpr, 0, sizeof(PortalOpr));

            std::memcpy(conn_->portalOpr, comm.portalOpr, sizeof(PortalOpr));

            copyKeyVal(&comm.portalOpr->dataOprInp.condInput, &conn_->portalOpr->dataOprInp.condInput);
        }

        if (nullptr != comm.reconnAddr) {
            // TODO: Should we cap this?
            const auto buffer_size = std::strlen(comm.reconnAddr) + 1;
            conn_->reconnAddr = static_cast<char*>(std::malloc(buffer_size));
            std::strncpy(conn_->reconnAddr, comm.reconnAddr, buffer_size - 1);
        }

        if (nullptr != comm.auth_scheme) {
            // TODO: Should we cap this?
            const auto buffer_size = std::strlen(comm.auth_scheme) + 1;
            conn_->auth_scheme = static_cast<char*>(std::malloc(buffer_size));
            std::strncpy(conn_->auth_scheme, comm.auth_scheme, buffer_size - 1);
        }

        // You should not copy / reuse SSL instances because this is an active SSL session. It should in fact be
        // discarded since it is owned by the input struct.
        if (nullptr != conn_->ssl) {
            conn_->ssl = nullptr;
        }

        // TODO: Do we need to do this?
        //replErrorStack(&comm.rError, &conn_->rError);

        copyKeyVal(&comm.session_props, &conn_->session_props);
    } // server_connection::copy
#endif
} // namespace irods
