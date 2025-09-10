#include "irods/authentication_plugin_framework.hpp"

#include "irods/authenticate.h"
#include "irods/authentication_client_utils.hpp"
#include "irods/irods_auth_constants.hpp"
#include "irods/irods_exception.hpp"
#include "irods/irods_stacktrace.hpp"
#include "irods/msParam.h"
#include "irods/rcConnect.h"
#include "irods/rodsDef.h"

#ifdef RODS_SERVER
#  include "irods/icatHighLevelRoutines.hpp"
#  include "irods/irods_client_server_negotiation.hpp"
#  include "irods/irods_logger.hpp"
#  include "irods/irods_rs_comm_query.hpp"
#  define IRODS_USER_ADMINISTRATION_ENABLE_SERVER_SIDE_API
#  include "irods/user_administration.hpp"
#endif // RODS_SERVER

#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>

#include <fmt/format.h>

namespace
{
#ifdef RODS_SERVER
    using log_auth = irods::experimental::log::authentication;
    namespace adm = irods::experimental::administration;
#endif // RODS_SERVER
    using json = nlohmann::json;
    namespace irods_auth = irods::authentication;

    auto get_password_file_path() -> std::optional<std::filesystem::path>
    {
        // TODO(#XXXX): Consider caching the path in a static variable once found.
        // See whether the environment has a variable which specifies where the session token file is located.
        constexpr const char* password_file_env_var = "IRODS_SESSION_TOKEN_FILE_PATH";
        const char* env_var = std::getenv(password_file_env_var);
        if (env_var && '\0' != *env_var) {
            return std::filesystem::path{env_var};
        }
        // If no HOME environment variable is set, this is not an error. We just don't know where the session token
        // file is located, so we must return nothing.
        const char* home_var = std::getenv("HOME");
        if (!home_var) {
            return std::nullopt;
        }
        constexpr const char* password_filename_default = ".irods/.irods_secrets";
        return std::filesystem::path{home_var} / password_filename_default;
    } // get_password_file_path

    auto get_password_from_file() -> std::optional<std::string>
    {
        const auto password_file_path = get_password_file_path();
        if (!password_file_path || !std::filesystem::exists(*password_file_path)) {
            return std::nullopt;
        }
        std::ifstream password_file_stream{password_file_path->c_str()};
        if (!password_file_stream.is_open()) {
            const auto ec = UNIX_FILE_OPEN_ERR - errno;
            THROW(
                ec,
                fmt::format("Failed to open session token file [{}]. errno:[{}]", password_file_path->c_str(), errno));
        }
        // TODO(#XXXX): Limit the number of characters read in here. Session tokens should be a fixed length.
        // TODO(#XXXX): Might also consider a JSON format. For now, just expect the contents to be the session token.
        std::string password_file_contents;
        password_file_stream >> password_file_contents;
        return password_file_contents;
    } // get_password_from_file

    auto write_password_to_file(const std::string& _password) -> void
    {
        const auto password_file_path = get_password_file_path();
        if (!password_file_path) {
            return;
        }
        std::ofstream password_file_stream{password_file_path->c_str()};
        if (!password_file_stream.is_open()) {
            // TODO: Is this really an error?
            const auto ec = UNIX_FILE_OPEN_ERR - errno;
            THROW(
                ec,
                fmt::format("Failed to open session token file [{}]. errno:[{}]", password_file_path->c_str(), errno));
        }
        // TODO(#XXXX): Limit the number of characters read in here. Passwords should have a max length.
        // TODO(#XXXX): Might also consider a JSON format. For now, just expect the contents to be the session token.
        password_file_stream << _password;
        password_file_stream.close();
        // Make sure that only the owner can read/write this file because it contains sensitive information.
        std::filesystem::permissions(
            password_file_path->c_str(), std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
    } // write_password_to_file

#ifdef RODS_SERVER
    auto set_privileges_in_rs_comm(RsComm& _comm, const std::string& _user_name, const std::string& _zone_name) -> void
    {
        zoneInfo_t* local_zone_info{};
        if (const auto ec = getLocalZoneInfo(&local_zone_info); ec < 0) {
            THROW(ec, "getLocalZoneInfo failed.");
        }
        // First make sure the proxy and client user's zone information is populated. If not, set it to local zone.
        if ('\0' == _comm.proxyUser.rodsZone[0]) {
            std::strncpy(_comm.proxyUser.rodsZone, local_zone_info->zoneName, NAME_LEN);
        }
        if ('\0' == _comm.clientUser.rodsZone[0]) {
            std::strncpy(_comm.clientUser.rodsZone, local_zone_info->zoneName, NAME_LEN);
        }
        // Get the user type of the user whose password was just verified.
        const auto user = adm::user{_user_name, _zone_name};
        const auto user_type = adm::server::type(_comm, user);
        if (!user_type) {
            THROW(CAT_INVALID_USER_TYPE, fmt::format("Failed to get user type for [{}#{}].", user.name, user.zone));
        }
        // Set the privilege level based on the returned user type and whether user is local to this zone.
        // TODO: Might need to change this based on whether we are connected to "REMOTE_ICAT"?
        int user_privilege_level = NO_USER_AUTH;
        switch (*user_type) {
            case adm::user_type::rodsadmin:
                user_privilege_level =
                    (user.zone != local_zone_info->zoneName) ? REMOTE_PRIV_USER_AUTH : LOCAL_PRIV_USER_AUTH;
                break;
            case adm::user_type::groupadmin:
                [[fallthrough]];
            case adm::user_type::rodsuser:
                user_privilege_level = (user.zone != local_zone_info->zoneName) ? REMOTE_USER_AUTH : LOCAL_USER_AUTH;
                break;
            default:
                THROW(CAT_INVALID_USER_TYPE,
                      fmt::format("User [{}#{}] has invalid user type [{}].",
                                  user.name,
                                  user.zone,
                                  static_cast<int>(*user_type)));
        }
        // Now set client user privilege level. If the user is acting on behalf of itself, just use the same
        // privilege level for both the proxy and client users.
        int client_user_privilege_level = NO_USER_AUTH;
        if (0 == strcmp(_comm.proxyUser.userName, _comm.clientUser.userName) &&
            0 == strcmp(_comm.proxyUser.rodsZone, _comm.clientUser.rodsZone))
        {
            client_user_privilege_level = user_privilege_level;
        }
        else {
            const auto client_user = adm::user{_comm.clientUser.userName, _comm.clientUser.rodsZone};
            const auto client_user_type = adm::server::type(_comm, client_user);
            if (!client_user_type) {
                THROW(CAT_INVALID_USER_TYPE,
                      fmt::format(
                          "Failed to get user type for client user [{}#{}].", client_user.name, client_user.zone));
            }
            switch (*client_user_type) {
                case adm::user_type::rodsadmin:
                    client_user_privilege_level =
                        (client_user.zone != local_zone_info->zoneName) ? REMOTE_PRIV_USER_AUTH : LOCAL_PRIV_USER_AUTH;
                    break;
                case adm::user_type::groupadmin:
                    [[fallthrough]];
                case adm::user_type::rodsuser:
                    client_user_privilege_level =
                        (client_user.zone != local_zone_info->zoneName) ? REMOTE_USER_AUTH : LOCAL_USER_AUTH;
                    break;
                default:
                    THROW(CAT_INVALID_USER_TYPE,
                          fmt::format("Client user [{}#{}] has invalid user type [{}].",
                                      client_user.name,
                                      client_user.zone,
                                      static_cast<int>(*client_user_type)));
            }
        }
        irods::throw_on_insufficient_privilege_for_proxy_user(_comm, user_privilege_level);
        _comm.proxyUser.authInfo.authFlag = user_privilege_level;
        _comm.clientUser.authInfo.authFlag = client_user_privilege_level;
    } // set_privileges_in_rs_comm

    auto auth_scheme_requires_secure_communications(const std::string& _auth_scheme) -> bool
    {
        constexpr const char* KW_CFG_PAM_INTERACTIVE_INSECURE_MODE = "insecure_mode";
        const auto config_path = irods::configuration_parser::key_path_t{
            irods::KW_CFG_PLUGIN_CONFIGURATION, "authentication", _auth_scheme, KW_CFG_PAM_INTERACTIVE_INSECURE_MODE};
        try {
            // Return the negation of the configuration's value because the configuration is "insecure_mode", but this
            // function is returning whether secure communications are required. So, if insecure_mode is set to true, we
            // should return false for this function; and vice-versa.
            return !irods::get_server_property<const bool>(config_path);
        }
        catch (const irods::exception& e) {
            if (KEY_NOT_FOUND == e.code()) {
                // If the plugin configuration is not set, default to requiring secure communications.
                return true;
            }
            // Re-throw for any other error.
            throw;
        }
        catch (const json::exception& e) {
            THROW(CONFIGURATION_ERROR,
                  fmt::format("Error occurred while attempting to get the value of server configuration [{}]: {}",
                              fmt::join(config_path, "."),
                              e.what()));
        }
    } // auth_scheme_requires_secure_communications

    auto throw_if_secure_communications_required() -> void
    {
        if (auth_scheme_requires_secure_communications("basic")) {
            THROW(SYS_NOT_ALLOWED,
                  "Client communications with this server are not secure and this authentication plugin is "
                  "configured to require TLS/SSL communication. Authentication is not allowed unless this server "
                  "is configured to require TLS/SSL in order to prevent leaking sensitive user information.");
        }
    } // throw_if_secure_communications_required

    auto log_warning_for_insecure_mode() -> void
    {
        log_auth::warn("Client communications with this server are not secure, and sensitive user information is "
                       "being communicated over the network in an unencrypted manner. Configure this server to "
                       "require TLS/SSL to prevent security leaks.");
    } // log_warning_for_insecure_mode
#endif // RODS_SERVER
} // anonymous namespace

namespace irods
{
    class basic_authentication : public irods_auth::authentication_base
    {
      private:
        // Operation names
        static constexpr const char* client_init_auth_with_server = "client_init_auth_with_server";
        static constexpr const char* client_prepare_auth_check = "client_prepare_auth_check";
        static constexpr const char* client_auth_with_password = "client_auth_with_password";
        static constexpr const char* server_prepare_auth_check = "server_prepare_auth_check";
        static constexpr const char* server_auth_with_password = "server_auth_with_password";

        // Other keys / constants
        static constexpr const char* password_kw = "password";
        static constexpr const char* user_name_kw = "user_name";
        static constexpr const char* zone_name_kw = "zone_name";

      public:
        basic_authentication()
        {
            add_operation(client_init_auth_with_server, OPERATION(RcComm, client_init_auth_with_server_op));
            add_operation(client_prepare_auth_check, OPERATION(RcComm, client_prepare_auth_check_op));
            add_operation(client_auth_with_password, OPERATION(RcComm, client_auth_with_password_op));
#ifdef RODS_SERVER
            add_operation(server_prepare_auth_check, OPERATION(RsComm, server_prepare_auth_check_op));
            add_operation(server_auth_with_password, OPERATION(RsComm, server_auth_with_password_op));
#endif
        } // ctor

      private:
        json auth_client_start(rcComm_t& comm, const json& req)
        {
            json resp{req};
            resp[user_name_kw] = comm.proxyUser.userName;
            resp[zone_name_kw] = comm.proxyUser.rodsZone;
            resp[irods_auth::next_operation] = client_init_auth_with_server;
            return resp;
        } // auth_client_start

        auto client_init_auth_with_server_op(RcComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            nlohmann::json svr_req{_request};
            svr_req[irods_auth::next_operation] = server_prepare_auth_check;
            auto resp = irods_auth::request(_comm, svr_req);
            resp[irods_auth::next_operation] = client_prepare_auth_check;
            return resp;
        } // client_init_auth_with_server_op

        auto client_prepare_auth_check_op(RcComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(_request, {user_name_kw, zone_name_kw});
            nlohmann::json resp{_request};
            const auto force_prompt = _request.find(irods_auth::force_password_prompt);
            if (_request.end() != force_prompt && force_prompt->get<bool>()) {
                fmt::print("Enter your iRODS password:");
                resp[password_kw] = irods::authentication::get_password_from_client_stdin();
                resp[irods_auth::next_operation] = client_auth_with_password;
                return resp;
            }
            // The anonymous user does not require a session token or password to authenticate.
            if (ANONYMOUS_USER == _request.at(user_name_kw).get_ref<const std::string&>()) {
                resp[password_kw] = "";
                resp[irods_auth::next_operation] = client_auth_with_password;
                return resp;
            }
            // If a password is provided by the client to the plugin, authenticate with that.
            const auto provided_password = _request.find(password_kw);
            if (_request.end() != provided_password) {
                resp[password_kw] = provided_password->get_ref<const std::string&>();
                resp[irods_auth::next_operation] = client_auth_with_password;
                return resp;
            }
            const auto discovered_password = get_password_from_file();
            if (discovered_password && !discovered_password->empty()) {
                resp[password_kw] = *discovered_password;
                resp[irods_auth::next_operation] = client_auth_with_password;
                return resp;
            }
            // If no session token was provided, no session token is found in the local file, no password is provided,
            // AND the user is not anonymous, get the password from stdin. This is the last resort.
            fmt::print("Enter your iRODS password:");
            resp[password_kw] = irods::authentication::get_password_from_client_stdin();
            resp[irods_auth::next_operation] = client_auth_with_password;
            return resp;
        } // client_prepare_auth_check_op

        auto client_auth_with_password_op(RcComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(_request, {user_name_kw, zone_name_kw, password_kw});
            nlohmann::json svr_req{_request};
            svr_req[irods_auth::next_operation] = server_auth_with_password;
            auto resp = irods_auth::request(_comm, svr_req);
            if (const auto record_auth_file_iter = _request.find(irods_auth::record_auth_file);
                _request.end() != record_auth_file_iter && record_auth_file_iter->get<bool>())
            {
                write_password_to_file(_request.at(password_kw).get_ref<const std::string&>());
            }
            _comm.loggedIn = 1;
            resp[irods_auth::next_operation] = irods_auth::flow_complete;
            return resp;
        } // client_auth_with_password_op

#ifdef RODS_SERVER
        auto server_prepare_auth_check_op(RsComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            nlohmann::json resp{_request};
            if (_comm.auth_scheme) {
                std::free(_comm.auth_scheme);
            }
            _comm.auth_scheme = strdup("basic");
            // Make sure the connection is secured before proceeding. If the connection is not secure, a warning will be
            // displayed in the server log at the very least. If the plugin is not configured to allow for insecure
            // communications between the client and server, the authentication attempt is rejected outright.
            if (irods::CS_NEG_USE_SSL != _comm.negotiation_results) {
                throw_if_secure_communications_required();
                log_warning_for_insecure_mode();
            }
            return resp;
        } // server_prepare_auth_check_op

        auto server_auth_with_password_op(RsComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            // Make sure the connection is secured before proceeding. If the connection is not secure, a warning will be
            // displayed in the server log at the very least. If the plugin is not configured to allow for insecure
            // communications between the client and server, the authentication attempt is rejected outright.
            if (irods::CS_NEG_USE_SSL != _comm.negotiation_results) {
                throw_if_secure_communications_required();
                log_warning_for_insecure_mode();
            }
            irods_auth::throw_if_request_message_is_missing_key(_request, {password_kw, zone_name_kw, user_name_kw});
            // Need to do NoLogin because it could get into inf loop for cross zone auth.
            rodsServerHost_t* host;
            const auto& zone_name = _request.at(zone_name_kw).get_ref<const std::string&>();
            int status = getAndConnRcatHostNoLogin(&_comm, PRIMARY_RCAT, zone_name.c_str(), &host);
            if (status < 0) {
                THROW(status, fmt::format("Failed to connect to catalog service provider: [{}]", status));
            }
            // What follows in this operation requires access to database operations, so continue on the catalog
            // provider.
            if (LOCAL_HOST != host->localFlag) {
                // In addition to the client-server connection, the server-to-server connection which occurs between the
                // local server and the catalog service provider must be secured as well. If the connection is not
                // secure, a warning will be displayed in the server log at the very least. If the plugin is not
                // configured to allow for insecure communications between the client (in this case, also a server) and
                // server, the authentication attempt is rejected outright.
                if (irods::CS_NEG_USE_SSL != _comm.negotiation_results) {
                    throw_if_secure_communications_required();
                    log_warning_for_insecure_mode();
                }
                // Note: We should not disconnect this server-to-server connection because the connection is not owned
                // by this context. A set of server-to-server connections is maintained by the server agent and reused
                // by various APIs and operations as needed.
                return irods_auth::request(*host->conn, _request);
            }
            // Check the provided username / password combination.
            const auto& user_name = _request.at(user_name_kw).get_ref<const std::string&>();
            const auto& password = _request.at(password_kw).get_ref<const std::string&>();
            int valid = 0;
            const int ec = chl_check_password(&_comm, user_name.c_str(), zone_name.c_str(), password.c_str(), &valid);
            if (ec < 0) {
                THROW(ec,
                      fmt::format(
                          "Error occurred while checking password for user [{}#{}]: {}", user_name, zone_name, ec));
            }
            if (!valid) {
                THROW(
                    AUTHENTICATION_ERROR, fmt::format("Authentication failed for user [{}#{}].", user_name, zone_name));
            }
            // Success! Now set user privilege information in the RsComm. This could be its own operation, but then we
            // would require the client to call the operation.
            set_privileges_in_rs_comm(_comm, user_name, zone_name);
            nlohmann::json resp{_request};
            return resp;
        } // server_auth_with_password_op
#endif
    }; // class basic_authentication
} // namespace irods

extern "C" irods::basic_authentication* plugin_factory(const std::string&, const std::string&)
{
    return new irods::basic_authentication{};
}
