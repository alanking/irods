#include "irods/authentication_plugin_framework.hpp"

#include "irods/authenticate.h"
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

#include <termios.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <sstream>

namespace
{
#ifdef RODS_SERVER
    using log_auth = irods::experimental::log::authentication;
#endif // RODS_SERVER
    namespace irods_auth = irods::experimental::auth;
} // anonymous namespace

namespace irods
{
    class basic_authentication : public irods_auth::authentication_base {
      private:
        static constexpr const char* basic_auth_scheme_name = "basic";
        static constexpr const char* client_init_auth_with_server = "client_init_auth_with_server";
        static constexpr const char* client_prepare_auth_check = "client_prepare_auth_check";
        static constexpr const char* client_perform_auth_check = "client_perform_auth_check";
        static constexpr const char* server_prepare_auth_check = "server_prepare_auth_check";
        static constexpr const char* server_perform_auth_check = "server_perform_auth_check";

      public:
        native_authentication()
        {
            add_operation(client_init_auth_with_server, OPERATION(RcComm, client_init_auth_with_server_op));
            add_operation(client_prepare_auth_check, OPERATION(RcComm, client_prepare_auth_check_op));
            add_operation(client_perform_auth_check, OPERATION(RcComm, client_perform_auth_check_op));
#ifdef RODS_SERVER
            add_operation(server_prepare_auth_check, OPERATION(RsComm, server_prepare_auth_check_op));
            add_operation(server_perform_auth_check, OPERATION(RsComm, server_perform_auth_check_op));
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
            char password_buf[MAX_PASSWORD_LEN + 1]{};
            // determine if a password challenge is needed, are we anonymous or not?
            bool need_password = false;
            if (_request.at("user_name").get_ref<const std::string&>() != ANONYMOUS_USER) {
                // And do we have an .irodsA file with a password in it?
                // TODO: We need to check for a token here??
                //need_password = obfGetPw(password_buf);
                need_password = true;
            }
            // prompt for a password if necessary
            if (need_password) {
                struct termios tty;
                memset(&tty, 0, sizeof(tty));
                tcgetattr(STDIN_FILENO, &tty);
                tcflag_t oldflag = tty.c_lflag;
                tty.c_lflag &= ~ECHO;
                int error = tcsetattr(STDIN_FILENO, TCSANOW, &tty);
                int errsv = errno;
                if (error) {
                    fmt::print("WARNING: Error {} disabling echo mode. "
                               "Password will be displayed in plaintext.\n",
                               errsv);
                }
                fmt::print("Enter your current iRODS password:");
                std::string password{};
                getline(std::cin, password);
                // TODO: If password exceeds MAX_PASSWORD_LEN, this will still succeed...
                std::strncpy(password_buf, password.c_str(), MAX_PASSWORD_LEN);
                fmt::print("\n");
                tty.c_lflag = oldflag;
                if (tcsetattr(STDIN_FILENO, TCSANOW, &tty)) {
                    fmt::print("Error reinstating echo mode.");
                }
            }
#if 0
            //char digest[RESPONSE_LEN + 2]{};
            unsigned char out[RESPONSE_LEN * 2]{};
            unsigned long out_len{RESPONSE_LEN * 2};
            auto err = base64_encode(reinterpret_cast<unsigned char*>(password_buf), RESPONSE_LEN, out, &out_len);
            if (err < 0) {
                THROW(err, "base64 encoding of digest failed.");
            }
            resp["digest"] = std::string{reinterpret_cast<char*>(out), out_len};
#endif
            resp["digest"] = password_buf;
            resp[irods_auth::next_operation] = client_perform_auth_check;
            return resp;
        } // client_prepare_auth_check_op

        auto client_perform_auth_check_op(RcComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(
                _request, {"digest", "user_name", "zone_name"}
            );
            nlohmann::json svr_req{_request};
            svr_req[irods_auth::next_operation] = server_perform_auth_check;
            auto resp = irods_auth::request(_comm, svr_req);
            _comm.loggedIn = 1;
            resp[irods_auth::next_operation] = irods_auth::flow_complete;
            return resp;
        } // client_perform_auth_check_op

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

        auto server_perform_auth_check_op(RsComm& _comm, const nlohmann::json& _request) -> nlohmann::json
        {
            irods_auth::throw_if_request_message_is_missing_key(_request, {"digest", "zone_name", "user_name"});
            // need to do NoLogin because it could get into inf loop for cross zone auth
            rodsServerHost_t* rodsServerHost;
            auto zone_name = _request.at("zone_name").get<std::string>();
            int status =
                getAndConnRcatHostNoLogin(&_comm, PRIMARY_RCAT, const_cast<char*>(zone_name.c_str()), &rodsServerHost);
            if (status < 0) {
                THROW(status, "Connecting to rcat host failed.");
            }
#if 0
            char* response = static_cast<char*>(malloc(RESPONSE_LEN + 1));
            std::memset(response, 0, RESPONSE_LEN + 1);
            const auto free_response = irods::at_scope_exit{[response] { free(response); }};
            response[RESPONSE_LEN] = 0;
            unsigned long out_len = RESPONSE_LEN;
            auto to_decode = _request.at("digest").get<std::string>();
            auto err = base64_decode(reinterpret_cast<unsigned char*>(const_cast<char*>(to_decode.c_str())),
                                     to_decode.size(),
                                     reinterpret_cast<unsigned char*>(response),
                                     &out_len);
            if (err < 0) {
                THROW(err, "base64 decoding of digest failed.");
            }
#endif
            authCheckInp_t authCheckInp{};
            authCheckInp.challenge = _rsAuthRequestGetChallenge();
            const auto& response = _request.at("digest").get_ref<const std::string&>();
            authCheckInp.response = response.c_str();
            // TODO: This is obviously not necessary if we use a new API endpoint.
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
            return resp;
        } // server_perform_auth_check_op
#endif
    }; // class native_authentication
} // namespace irods

extern "C"
irods::native_authentication* plugin_factory(const std::string&, const std::string&)
{
    return new irods::native_authentication{};
}

