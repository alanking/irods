#include "irods/authentication_plugin_framework.hpp"

#include "irods/authenticate.h"
#include "irods/irods_exception.hpp"
#include "irods/irods_stacktrace.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/msParam.h"
#include "irods/rcConnect.h"
#include "irods/rodsDef.h"

#ifdef RODS_SERVER
#include "irods/authCheck.h"
#include "irods/irods_logger.hpp"
#include "irods/irods_rs_comm_query.hpp"
#include "irods/rsAuthCheck.hpp"
#endif // RODS_SERVER

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <termios.h>
#include <unistd.h>

#include <fmt/format.h>

namespace
{
#ifdef RODS_SERVER
    using log_auth = irods::experimental::log::authentication;
#endif // RODS_SERVER
    namespace irods_auth = irods::experimental::auth;

    auto get_password_from_client_stdin() -> std::string
    {
        struct termios tty;
        tcgetattr(STDIN_FILENO, &tty);
        tcflag_t oldflag = tty.c_lflag;
        tty.c_lflag &= ~ECHO;
        if (const auto error = tcsetattr(STDIN_FILENO, TCSANOW, &tty); error) {
            const int errsv = errno;
            fmt::print("WARNING: Error {} disabling echo mode. Password will be displayed in plaintext.\n", errsv);
        }
        printf("Enter your current PAM password:");
        std::string password;
        getline(std::cin, password);
        printf("\n");
        tty.c_lflag = oldflag;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &tty)) {
            fmt::print("Error reinstating echo mode.\n");
        }
        return password;
    } // get_password_from_client_stdin

    auto get_session_token_file_path() -> std::optional<std::filesystem::path>
    {
        // TODO(#XXXX): Consider caching the path in a static variable once found.
        // See whether the environment has a variable which specifies where the session token file is located.
        constexpr const char* session_token_file_env_var = "IRODS_SESSION_TOKEN_FILE_PATH";
        const char* env_var = std::getenv(session_token_file_env_var);
        if (env_var && '\0' != *env_var) {
            return std::filesystem::path{env_var};
        }
        // If no HOME environment variable is set, this is not an error. We just don't know where the session token
        // file is located, so we must return nothing.
        const char* home_var = std::getenv("HOME");
        if (!home_var) {
            return std::nullopt;
        }
        constexpr const char* session_token_filename_default = ".irods/irods_session_token";
        return std::filesystem::path{home_var} / session_token_filename_default;
    } // get_session_token_file_path

    auto get_session_token_from_file() -> std::optional<std::string>
    {
        const auto session_token_file_path = get_session_token_file_path();
        if (!session_token_file_path || !std::filesystem::exists(*session_token_file_path)) {
            return std::nullopt;
        }
        std::ifstream session_token_file_stream{session_token_file_path->c_str()};
        if (!session_token_file_stream.is_open()) {
            const auto ec = UNIX_FILE_OPEN_ERR - errno;
            THROW(ec, fmt::format("Failed to open session token file [{}]. errno:[{}]", session_token_file_path->c_str(), errno));
        }
        // TODO(#XXXX): Limit the number of characters read in here. Session tokens should be a fixed length.
        // TODO(#XXXX): Might also consider a JSON format. For now, just expect the contents to be the session token.
        std::string session_token_file_contents;
        session_token_file_stream >> session_token_file_contents;
        return session_token_file_contents;
    } // get_session_token_from_file

    auto write_session_token_to_file(const std::string& _session_token) -> void
    {
        const auto session_token_file_path = get_session_token_file_path();
        if (!session_token_file_path) {
            return;
        }
        // TODO(#XXXX): Is it an error to record the session token to the file? What if the client doesn't want to do 
        // that?
        std::ofstream session_token_file_stream{session_token_file_path->c_str()};
        if (!session_token_file_stream.is_open()) {
            const auto ec = UNIX_FILE_OPEN_ERR - errno;
            THROW(ec, fmt::format("Failed to open session token file [{}]. errno:[{}]", session_token_file_path->c_str(), errno));
        }
        // TODO(#XXXX): Limit the number of characters read in here. Session tokens should be a fixed length.
        // TODO(#XXXX): Might also consider a JSON format. For now, just expect the contents to be the session token.
        session_token_file_stream << _session_token;
    } // write_session_token_to_file
} // anonymous namespace

namespace irods
{
    class basic_authentication : public irods_auth::authentication_base {
      private:
        static constexpr const char* basic_auth_scheme_name = "basic";
        static constexpr const char* client_init_auth_with_server = "client_init_auth_with_server";
        static constexpr const char* client_prepare_auth_check = "client_prepare_auth_check";
        static constexpr const char* client_auth_with_password = "client_auth_with_password";
        static constexpr const char* client_auth_with_session_token = "client_auth_with_session_token";
        static constexpr const char* server_prepare_auth_check = "server_prepare_auth_check";
        static constexpr const char* server_auth_with_password = "server_auth_with_password";
        static constexpr const char* server_auth_with_session_token = "server_auth_with_session_token";

      public:
        basic_authentication()
        {
            add_operation(client_init_auth_with_server, OPERATION(RcComm, client_init_auth_with_server_op));
            add_operation(client_prepare_auth_check, OPERATION(RcComm, client_prepare_auth_check_op));
            add_operation(client_auth_with_password, OPERATION(RcComm, client_auth_with_password_op));
            add_operation(client_auth_with_session_token, OPERATION(RcComm, client_auth_with_session_token_op));
#ifdef RODS_SERVER
            add_operation(server_prepare_auth_check, OPERATION(RsComm, server_prepare_auth_check_op));
            add_operation(server_auth_with_password, OPERATION(RsComm, server_auth_with_password_op));
            add_operation(server_auth_with_session_token, OPERATION(RsComm, server_auth_with_session_token_op));
#endif
        } // ctor

    private:
        auto auth_client_start(RcComm& _comm, const nlohmann::json& _req) -> nlohmann::json
        {
            auto resp{_req};
            resp["user_name"] = _comm.proxyUser.userName;
            resp["zone_name"] = _comm.proxyUser.rodsZone;
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
            irods_auth::throw_if_request_message_is_missing_key(_request, {"user_name", "zone_name"});
            nlohmann::json resp{_request};
            // The anonymous user does not require a session token or password to authenticate.
            if (ANONYMOUS_USER == _request.at("user_name").get_ref<const std::string&>()) {
                resp["password"] = "";
                resp[irods_auth::next_operation] = client_auth_with_password;
                return resp;
            }
            // If a session token is provided by the client to the plugin, autheticate with that.
            const auto provided_session_token = _request.find("session_token");
            if (_request.end() != provided_session_token) {
                resp["session_token"] = provided_session_token->get_ref<const std::string&>();
                resp[irods_auth::next_operation] = client_auth_with_session_token;
                return resp;
            }
            // If a password is provided by the client to the plugin, authenticate with that.
            const auto provided_password = _request.find("password");
            if (_request.end() != provided_password) {
                resp["password"] = provided_password->get_ref<const std::string&>();
                resp[irods_auth::next_operation] = client_auth_with_password;
                return resp;
            }
            // If neither a session token nor a password was provided, look for a session token in a local file.
            const auto discovered_session_token = get_session_token_from_file();
            if (discovered_session_token && !discovered_session_token->empty()) {
                resp["session_token"] = *discovered_session_token;
                resp[irods_auth::next_operation] = client_auth_with_session_token;
                return resp;
            }
            // If no session token was provided, no session token is found in the local file, no password is provided,
            // AND the user is not anonymous, get the password from stdin. This is the last resort.
            resp["password"] = get_password_from_client_stdin();
            resp[irods_auth::next_operation] = client_auth_with_password;
            return resp;
        } // client_prepare_auth_check_op

        auto client_auth_with_password_op(RcComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(_request, {"user_name", "zone_name", "password"});
            nlohmann::json svr_req{_request};
            svr_req[irods_auth::next_operation] = server_auth_with_password;
            auto resp = irods_auth::request(_comm, svr_req);
            _comm.loggedIn = 1;
            resp[irods_auth::next_operation] = irods_auth::flow_complete;
            return resp;
        } // client_auth_with_password_op

        auto client_auth_with_session_token_op(RcComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(_request, {"user_name", "zone_name", "session_token"});
            nlohmann::json svr_req{_request};
            svr_req[irods_auth::next_operation] = server_auth_with_session_token;
            auto resp = irods_auth::request(_comm, svr_req);
            _comm.loggedIn = 1;
            resp[irods_auth::next_operation] = irods_auth::flow_complete;
            return resp;
        } // client_auth_with_session_token_op

#ifdef RODS_SERVER
        auto server_prepare_auth_check_op(RsComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            nlohmann::json resp{_request};
            if (_comm.auth_scheme) {
                free(_comm.auth_scheme);
            }
            _comm.auth_scheme = strdup(basic_auth_scheme_name);
            return resp;
        } // server_prepare_auth_check_op

        auto server_auth_with_password_op(RsComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(_request, {"password", "zone_name", "user_name"});
            // need to do NoLogin because it could get into inf loop for cross zone auth
            rodsServerHost_t* rodsServerHost;
            auto zone_name = _request.at("zone_name").get<std::string>();
            int status =
                getAndConnRcatHostNoLogin(&_comm, PRIMARY_RCAT, const_cast<char*>(zone_name.c_str()), &rodsServerHost);
            if (status < 0) {
                THROW(status, "Connecting to rcat host failed.");
            }
            authCheckInp_t authCheckInp{};
            authCheckInp.challenge = "";
            const auto& response = _request.at("password").get_ref<const std::string&>();
            authCheckInp.response = const_cast<char*>(response.c_str());
            // TODO(#XXXX): This is obviously not necessary if we use a new API endpoint.
            addKeyVal(&authCheckInp.cond_input, "use_password_hash", "");
            const std::string username =
                fmt::format("{}#{}", _request.at("user_name").get_ref<const std::string&>(), zone_name);
            authCheckInp.username = const_cast<char*>(username.data());
            authCheckOut_t* authCheckOut = nullptr;
            if (LOCAL_HOST == rodsServerHost->localFlag) {
                status = rsAuthCheck(&_comm, &authCheckInp, &authCheckOut);
            }
            else {
                status = rcAuthCheck(rodsServerHost->conn, &authCheckInp, &authCheckOut);
                /* not likely we need this connection again */
                rcDisconnect(rodsServerHost->conn);
                rodsServerHost->conn = nullptr;
            }
            if (status < 0 || !authCheckOut) {
                THROW(status, "rcAuthCheck failed.");
            }
            nlohmann::json resp{_request};
            /* Set the clientUser zone if it is null. */
            if ('\0' == _comm.clientUser.rodsZone[0]) {
                zoneInfo_t* tmpZoneInfo{};
                status = getLocalZoneInfo(&tmpZoneInfo);
                if (status < 0) {
                    THROW(status, "getLocalZoneInfo failed.");
                }
                else {
                    strncpy(_comm.clientUser.rodsZone, tmpZoneInfo->zoneName, NAME_LEN);
                }
            }
            /* have to modify privLevel if the icat is a foreign icat because
             * a local user in a foreign zone is not a local user in this zone
             * and vice versa for a remote user
             */
            if (rodsServerHost->rcatEnabled == REMOTE_ICAT) {
                /* proxy is easy because rodsServerHost is based on proxy user */
                if (authCheckOut->privLevel == LOCAL_PRIV_USER_AUTH) {
                    authCheckOut->privLevel = REMOTE_PRIV_USER_AUTH;
                }
                else if (authCheckOut->privLevel == LOCAL_USER_AUTH) {
                    authCheckOut->privLevel = REMOTE_USER_AUTH;
                }
                /* adjust client user */
                if (0 == strcmp(_comm.proxyUser.userName, _comm.clientUser.userName)) {
                    authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                }
                else {
                    zoneInfo_t* tmpZoneInfo;
                    status = getLocalZoneInfo(&tmpZoneInfo);
                    if (status < 0) {
                        THROW(status, "getLocalZoneInfo failed.");
                    }
                    else {
                        if (0 == strcmp(tmpZoneInfo->zoneName, _comm.clientUser.rodsZone)) {
                            /* client is from local zone */
                            if (REMOTE_PRIV_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                            }
                            else if (REMOTE_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = LOCAL_USER_AUTH;
                            }
                        }
                        else {
                            /* client is from remote zone */
                            if (LOCAL_PRIV_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                            }
                            else if (LOCAL_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                            }
                        }
                    }
                }
            }
            else if (0 == strcmp(_comm.proxyUser.userName, _comm.clientUser.userName)) {
                authCheckOut->clientPrivLevel = authCheckOut->privLevel;
            }
            irods::throw_on_insufficient_privilege_for_proxy_user(_comm, authCheckOut->privLevel);
            log_auth::debug(
                "rsAuthResponse set proxy authFlag to {}, client authFlag to {}, user:{} proxy:{} client:{}",
                authCheckOut->privLevel,
                authCheckOut->clientPrivLevel,
                authCheckInp.username,
                _comm.proxyUser.userName,
                _comm.clientUser.userName);
            if (strcmp(_comm.proxyUser.userName, _comm.clientUser.userName) != 0) {
                _comm.proxyUser.authInfo.authFlag = authCheckOut->privLevel;
                _comm.clientUser.authInfo.authFlag = authCheckOut->clientPrivLevel;
            }
            else { /* proxyUser and clientUser are the same */
                _comm.proxyUser.authInfo.authFlag = _comm.clientUser.authInfo.authFlag = authCheckOut->privLevel;
            }
            if (authCheckOut != NULL) {
                if (authCheckOut->serverResponse != NULL) {
                    free(authCheckOut->serverResponse);
                }
                free(authCheckOut);
            }
            // TODO(#XXXX): Now we need to get a session token so that the user can authenticate with that in the future.
            // TODO(#XXXX): Is this another API call? Should we try to invoke the database operation directly?
            // TODO(#XXXX): Should the auth check above be returning the session token?
            return resp;
        } // server_auth_with_password_op

        auto server_auth_with_session_token_op(RsComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(_request, {"session_token", "zone_name", "user_name"});
            // need to do NoLogin because it could get into inf loop for cross zone auth
            rodsServerHost_t* rodsServerHost;
            auto zone_name = _request.at("zone_name").get<std::string>();
            int status =
                getAndConnRcatHostNoLogin(&_comm, PRIMARY_RCAT, const_cast<char*>(zone_name.c_str()), &rodsServerHost);
            if (status < 0) {
                THROW(status, "Connecting to rcat host failed.");
            }
            authCheckInp_t authCheckInp{};
            authCheckInp.challenge = "";
            const auto& response = _request.at("session_token").get_ref<const std::string&>();
            authCheckInp.response = const_cast<char*>(response.c_str());
            // TODO(#XXXX): This is obviously not necessary if we use a new API endpoint.
            addKeyVal(&authCheckInp.cond_input, "use_password_hash", "");
            const std::string username =
                fmt::format("{}#{}", _request.at("user_name").get_ref<const std::string&>(), zone_name);
            authCheckInp.username = const_cast<char*>(username.data());
            authCheckOut_t* authCheckOut = nullptr;
            if (LOCAL_HOST == rodsServerHost->localFlag) {
                status = rsAuthCheck(&_comm, &authCheckInp, &authCheckOut);
            }
            else {
                status = rcAuthCheck(rodsServerHost->conn, &authCheckInp, &authCheckOut);
                /* not likely we need this connection again */
                rcDisconnect(rodsServerHost->conn);
                rodsServerHost->conn = nullptr;
            }
            if (status < 0 || !authCheckOut) {
                THROW(status, "rcAuthCheck failed.");
            }
            nlohmann::json resp{_request};
            /* Set the clientUser zone if it is null. */
            if ('\0' == _comm.clientUser.rodsZone[0]) {
                zoneInfo_t* tmpZoneInfo{};
                status = getLocalZoneInfo(&tmpZoneInfo);
                if (status < 0) {
                    THROW(status, "getLocalZoneInfo failed.");
                }
                else {
                    strncpy(_comm.clientUser.rodsZone, tmpZoneInfo->zoneName, NAME_LEN);
                }
            }
            /* have to modify privLevel if the icat is a foreign icat because
             * a local user in a foreign zone is not a local user in this zone
             * and vice versa for a remote user
             */
            if (rodsServerHost->rcatEnabled == REMOTE_ICAT) {
                /* proxy is easy because rodsServerHost is based on proxy user */
                if (authCheckOut->privLevel == LOCAL_PRIV_USER_AUTH) {
                    authCheckOut->privLevel = REMOTE_PRIV_USER_AUTH;
                }
                else if (authCheckOut->privLevel == LOCAL_USER_AUTH) {
                    authCheckOut->privLevel = REMOTE_USER_AUTH;
                }
                /* adjust client user */
                if (0 == strcmp(_comm.proxyUser.userName, _comm.clientUser.userName)) {
                    authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                }
                else {
                    zoneInfo_t* tmpZoneInfo;
                    status = getLocalZoneInfo(&tmpZoneInfo);
                    if (status < 0) {
                        THROW(status, "getLocalZoneInfo failed.");
                    }
                    else {
                        if (0 == strcmp(tmpZoneInfo->zoneName, _comm.clientUser.rodsZone)) {
                            /* client is from local zone */
                            if (REMOTE_PRIV_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                            }
                            else if (REMOTE_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = LOCAL_USER_AUTH;
                            }
                        }
                        else {
                            /* client is from remote zone */
                            if (LOCAL_PRIV_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                            }
                            else if (LOCAL_USER_AUTH == authCheckOut->clientPrivLevel) {
                                authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                            }
                        }
                    }
                }
            }
            else if (0 == strcmp(_comm.proxyUser.userName, _comm.clientUser.userName)) {
                authCheckOut->clientPrivLevel = authCheckOut->privLevel;
            }
            irods::throw_on_insufficient_privilege_for_proxy_user(_comm, authCheckOut->privLevel);
            log_auth::debug(
                "rsAuthResponse set proxy authFlag to {}, client authFlag to {}, user:{} proxy:{} client:{}",
                authCheckOut->privLevel,
                authCheckOut->clientPrivLevel,
                authCheckInp.username,
                _comm.proxyUser.userName,
                _comm.clientUser.userName);
            if (strcmp(_comm.proxyUser.userName, _comm.clientUser.userName) != 0) {
                _comm.proxyUser.authInfo.authFlag = authCheckOut->privLevel;
                _comm.clientUser.authInfo.authFlag = authCheckOut->clientPrivLevel;
            }
            else { /* proxyUser and clientUser are the same */
                _comm.proxyUser.authInfo.authFlag = _comm.clientUser.authInfo.authFlag = authCheckOut->privLevel;
            }
            if (authCheckOut != NULL) {
                if (authCheckOut->serverResponse != NULL) {
                    free(authCheckOut->serverResponse);
                }
                free(authCheckOut);
            }
            // TODO(#XXXX): Now we need to get a session token so that the user can authenticate with that in the future.
            // TODO(#XXXX): Is this another API call? Should we try to invoke the database operation directly?
            // TODO(#XXXX): Should the auth check above be returning the session token?
            return resp;
        } // server_auth_with_session_token_op
#endif
    }; // class basic_authentication
} // namespace irods

extern "C"
irods::basic_authentication* plugin_factory(const std::string&, const std::string&)
{
    return new irods::basic_authentication{};
} // plugin_factory
