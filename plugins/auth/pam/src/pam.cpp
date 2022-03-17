#include "irods/authentication_plugin_framework.hpp"

#define USE_SSL 1
#include "irods/sslSockComm.h"

#include "irods/authCheck.h"
#include "irods/authPluginRequest.h"
#include "irods/irods_auth_constants.hpp"
#include "irods/irods_client_server_negotiation.hpp"
#include "irods/irods_stacktrace.hpp"
#include "irods/rcConnect.h"
#include "irods/rodsDef.h"

#ifdef RODS_SERVER
#include "irods/rsAuthCheck.hpp"
#endif

#include <boost/lexical_cast.hpp>
#include <nlohmann/json.hpp>
#include <openssl/md5.h>

#include <sstream>
#include <string>
#include <iostream>
#include <unistd.h>
#include <algorithm>

#include <sys/types.h>
#include <sys/wait.h>

#ifdef RODS_SERVER
#include "pam_handshake/handshake_session.h"
#endif
#include "message.h"
#include "conversation.h"
#include "../whereami/whereami.hpp"

int get64RandomBytes( char *buf );
void setSessionSignatureClientside(char* _sig);

const char AUTH_PAM_INTERACTIVE_SCHEME[] = "pam_interactive";

#ifdef RODS_SERVER
const char PAM_STACK_NAME[] = "irods";
const char PAM_CHECKER[] = "/usr/sbin/pam_handshake_auth_check";
const int SESSION_TIMEOUT = 3600;
#endif

namespace
{
    using json = nlohmann::json;
    using log_auth = irods::experimental::log::authentication;

    class enum http
    {
        ok = 200,
        unauthorized = 401,
        authenticated = 202,
        error = 500
    }; // class enum http

    PamHandshake::Message::Context get_message_context()
    {
        return WhereAmI::getExecutableBaseName() != "iinit" &&
               WhereAmI::getExecutableBaseName() != "iinit.exe"
               ? PamHandshake::Message::Context::ICommand
               : PamHandshake::Message::Context::IInit;
    } // get_message_context

    void throw_if_key_is_missing_in_json(const json& in,
                                         const std::vector<const std::string&> keys)
    {
        for (const auto& k : keys) {
            if (!in.contains(k)) {
                THROW(KEY_NOT_FOUND, fmt::format(
                      fmt::runtime("[{}:{}] missing [{}]"),
                      __func__, __LINE__, k));
            }
        }
    } // throw_if_key_is_missing_in_json

    auto request(rcComm_t& comm, const json& msg)
    {
        auto str = msg.dump();

        bytesBuf_t inp;
        inp.buf = static_cast<void*>(const_cast<char*>(str.c_str()));
        inp.len = str.size();

        bytesBuf_t* resp{};
        auto ec = procApiRequest(&comm, 110000, static_cast<void*>(&inp), nullptr, reinterpret_cast<void**>(&resp), nullptr);

        if (ec < 0) {
            THROW(ec, "failed to perform request");
        }

        return json::parse(static_cast<char*>(resp->buf), static_cast<char*>(resp->buf) + resp->len);
    } // request

    std::string pam_auth_get_session(rcComm_t& _comm, const json& _req)
    {
        json svr_req{_req};
        svr_req["next_operation"] = AUTH_AGENT_AUTH_REQUEST;
        svr_req["METHOD"] = "POST";

        auto resp = request(comm, svr_req);

        throw_if_key_is_missing_in_json(resp, {"CODE", "SESSION"});

        if (const auto code = std::stoi(resp.at("CODE").get_ref<const std::string&>());
            code != http::ok) {
            THROW(REMOTE_SERVER_AUTHENTICATION_FAILURE, fmt::format(
                  fmt::runtime("[{}:{}] http code: [{}]"), __func__, __LINE__, code));
        }

        return resp.at("SESSION").get<std::string>();
    } // pam_auth_get_session

#ifdef RODS_SERVER
    using Session = PamHandshake::Session;

    json post(rsComm_t& comm, const auto& req)
    {
        auto session = Session::getSingleton(PAM_STACK_NAME, PAM_CHECKER, SESSION_TIMEOUT);

        json resp{req};
        resp["SESSION"] = "";
        resp["CODE"] = std::to_string(http:ok);

        return resp;
    } // post

    json get(rsComm_t& comm, const auto& req)
    {
        auto session = Session::getSingleton(PAM_STACK_NAME, PAM_CHECKER, SESSION_TIMEOUT);

        json resp{req};
        resp["SESSION"] = "";
        resp["CODE"] = std::to_string(http:ok);
        resp["STATE"] = Session::StateToString(session->getState());
        resp["MESSAGE"] = "";

        return resp;
    } // get

    json put(rsComm_t& comm, const auto& req)
    {
        auto itr = req.find("ANSWER");
        const std::string& answer = itr == req.end() ? "" : itr->second;

        auto session = Session::getSingleton(PAM_STACK_NAME, PAM_CHECKER, SESSION_TIMEOUT);

        auto p = session->pull(answer.c_str(), answer.size());

        json resp{req};
        resp["SESSION"] = "";
        resp["STATE"] = Session::StateToString(p.first);
        resp["MESSAGE"] = p.second;

        switch (p.first) {
            case Session::State::Authenticated:
                resp["CODE"] = std::to_string(http::authenticated);
                PamHandshake::Session::resetSingleton();
                break;

            case Session::State::NotAuthenticated:
                resp["CODE"] = std::to_string(http::unauthorized);
                PamHandshake::Session::resetSingleton();
                THROW(PAM_AUTH_PASSWORD_FAILED, "pam auth check failed");

            case Session::State::Error:
                resp["CODE"] = std::to_string(http::error);
                [[fallthrough]];
            case Session::State::Timeout:
                PamHandshake::Session::resetSingleton();
                THROW(REMOTE_SERVER_AUTHENTICATION_FAILURE, fmt::format(
                            fmt::runtime("pam aux service failure [{}] [{}]"),
                            Session::StateToString(p.first), p.second));

            default:
                resp["CODE"] = std::to_string(http::ok);
                break;
        }

        return resp;
    } // put

    json del(rsComm_t& comm, const auto& req)
    {
        PamHandshake::Session::resetSingleton();

        json resp{req};
        resp["SESSION"] = "";
        resp["CODE"] = std::to_string(http::ok);

        return resp;
    } // del
#endif
} // anonymous namespace

namespace irods
{
    class pam_authentication : public irods::experimental::auth::authentication_base {
    private:
        static constexpr char* perform_native_auth = "perform_native_auth";

    public:
        pam_authentication()
        {
            add_operation(AUTH_CLIENT_AUTH_REQUEST,  OPERATION(rcComm_t, pam_auth_client_request));
            //add_operation(AUTH_ESTABLISH_CONTEXT,    OPERATION(rcComm_t, pam_auth_establish_context));
            //add_operation(AUTH_CLIENT_AUTH_RESPONSE, OPERATION(rcComm_t, pam_auth_client_response));
            add_operation(perform_native_auth,       OPERATION(rcComm_t, pam_auth_client_perform_native_auth));
#ifdef RODS_SERVER
            add_operation(AUTH_AGENT_AUTH_REQUEST,   OPERATION(rsComm_t, pam_auth_agent_request));
            //add_operation(AUTH_AGENT_AUTH_RESPONSE,  OPERATION(rsComm_t, pam_auth_agent_response));
#endif
        } // ctor

    private:
        json auth_client_start(rcComm_t& comm, const json& req)
        {
            json resp{req};
            resp["next_operation"] = AUTH_CLIENT_AUTH_REQUEST;
            resp["user_name"] = comm.proxyUser.userName;
            resp["zone_name"] = comm.proxyUser.rodsZone;

            log_auth::trace("[{}:{}] [{}]", __func__, __LINE__, resp.dump());

            return resp;
        } // pam_auth_client_start

        json pam_auth_client_request(rcComm_t& comm, const json& req)
        {
            log_auth::trace("[{}:{}] [{}]", __func__, __LINE__, req.dump());

            PamHandshake::Message::Context message_context = get_message_context();

            const bool using_ssl = irods::CS_NEG_USE_SSL == comm.negotiation_results;
            const auto end_ssl_if_we_enabled_it = irods::at_scope_exit{[&comm, using_ssl] {
                if (!using_ssl)  {
                    sslEnd(&comm);
                }
            }};

            if (!using_ssl) {
                if (const int ec = sslStart(&comm); ec) {
                    THROW(ec, "failed to enable SSL");
                }
            }

            PamHandshake::Conversation conversation;
            try {
                conversation.load();
            }
            catch (const std::exception& e) {
                log_auth::warn("failed to load conversation file [{}]", e.what());
                conversation.reset();
            }

            auto session = pam_auth_get_session(comm, req);

            json svr_req{req};
            svr_req["next_operation"] = AUTH_AGENT_AUTH_REQUEST;
            svr_req["METHOD"] = "PUT";

            for (bool authenticated = false; !authenticated;) {
                log_auth::trace("[{}:{}] [{}]", __func__, __LINE__, svr_req.dump());

                svr_req["SESSION"] = session;

                auto resp = request(comm, svr_req);

                throw_if_key_is_missing_in_json(resp, {"request_result"});

                try {
                    PamHandshake::Message msg{resp.at("request_result").get_ref<const std::string&>()};
                    msg.applyPatch(conversation);

                    switch (msg.getState())
                    {
                        case PamHandshake::Message::State::Waiting:
                            svr_req["ANSWER"] = msg.input(conversation, message_context);
                            break;

                        case PamHandshake::Message::State::WaitingPw:
                            svr_req["ANSWER"] = msg.input_password(conversation, message_context);
                            break;

                        case PamHandshake::Message::State::Next:
                            msg.echo(message_context);
                            break;

                        case PamHandshake::Message::State::Authenticated:
                            authenticated = true;
                            break;

                        case PamHandshake::Message::State::NotAuthenticated:
                            THROW(PAM_AUTH_PASSWORD_FAILED, "pam auth check failed");

                        case PamHandshake::Message::State::Error:
                            THROW(REMOTE_SERVER_AUTHENTICATION_FAILURE, fmt::format(
                                  fmt::runtime("PAM error: [{}]"), msg.getMessage()));

                        case PamHandshake::Message::State::Timeout:
                            THROW(REMOTE_SERVER_AUTHENTICATION_FAILURE, "PAM timeout");

                        default:
                            THROW(SYS_UNKNOWN_ERROR, "Invalid state");
                    }
                }
                catch (const json::exception& e) {
                    THROW(SYS_LIBRARY_ERROR, fmt::format(
                          fmt::runtime("[{}:{}] - json error occurred [{}]"), __func__, __LINE__, e.what()));
                }
                catch (const std::exception& e) {
                    THROW(SYS_INTERNAL_ERR, fmt::format(
                          fmt::runtime("[{}:{}] - [{}]"), __func__, __LINE__, e.what()));
                }
            }

            resp["request_result"] = conversation.dump();
            resp["next_operation"] = perform_native_auth;
            //resp["next_operation"] = AUTH_ESTABLISH_CONTEXT;

            try {
                conversation.save(false);
            }
            catch (const std::exception& e) {
                THROW(SYS_INTERNAL_ERR, fmt::format(
                      fmt::runtime("failed to save PAM conversation [{}]"), e.what()));
            }

            log_auth::trace("[{}:{}] [{}]", __func__, __LINE__, resp.dump());

            return resp;
        } // pam_auth_client_request

#if 0
        json pam_auth_establish_context(rcComm_t&, const json& req)
        {
            throw_if_key_is_missing_in_json(req, {"request_result"});

            const auto& request_result = req.at("request_result").get_ref<const std::string&>();
            const std::size_t len = std::max(static_cast<std::size_t>(request_result.size() + 1),
                                             static_cast<std::size_t>(16));

            char* md5_buf = static_cast<char*>(std::malloc(len));
            const auto free_buf = irods::at_scope_exit{[md5_buf] { free(md5_buf); }};
            std::memset(md5_buf, 0, len);
            std::strcpy(md5_buf, request_result.c_str());

            setSessionSignatureClientside(md5_buf);

            MD5_CTX context;
            MD5_Init(&context);
            MD5_Update(&context, reinterpret_cast<unsigned char*>(md5_buf), request_result.size());

            char digest[RESPONSE_LEN + 2];
            MD5_Final(reinterpret_cast<unsigned char*>(digest), &context);

            for (int i = 0; i < RESPONSE_LEN; ++i) {
                if (digest[i] == '\0') {
                    digest[i]++;
                }
            }

            json resp{req};

            // TODO: base64 encode like in native?
            unsigned char out[RESPONSE_LEN*2];
            unsigned long out_len{RESPONSE_LEN*2};
            auto err = base64_encode(reinterpret_cast<unsigned char*>(digest), RESPONSE_LEN, out, &out_len);
            if (err < 0) {
                THROW(err, "base64 encoding of digest failed.");
            }

            resp["digest"] = std::string{reinterpret_cast<char*>(out), out_len};
            resp["next_operation"] = AUTH_CLIENT_AUTH_RESPONSE;

            return resp;
        } // pam_auth_establish_context

        json pam_auth_client_response(rcComm_t& comm, const json& req)
        {
            throw_if_key_is_missing_in_json(req, {"user_name", "zone_name", "digest"});

            json svr_req{req};
            svr_req["next_operation"] = AUTH_AGENT_AUTH_RESPONSE;

            auto resp = request(comm, svr_req);

            comm.loggedIn = 1;

            resp["next_operation"] = irods::flow_complete;

            return resp;
        } // pam_auth_client_response
#else
        json pam_auth_client_perform_native_auth(rcComm_t& comm, const json& req)
        {
            namespace irods_auth = irods::experimental::auth;

            // This operation is basically just running the entire native authentication flow
            // because this is how the PAM authentication plugin has worked historically. This
            // is done in order to minimize communications with the PAM server as iRODS does
            // not use proper "sessions".
            json resp{req};

            static constexpr char* auth_scheme_native = "native";
            rodsEnv env{};
            std::strncpy(env.rodsAuthScheme, auth_scheme_native, NAME_LEN);
            irods_auth::authenticate_client(comm, env, json{});

            // If everything completes successfully, the flow is completed and we can
            // consider the user "logged in". Again, the entire native authentication flow
            // was run and so we trust the result.
            resp["next_operation"] = irods_auth::flow_complete;

            comm.loggedIn = 1;

            return resp;
        } // pam_auth_client_perform_native_auth
#endif // 0

#ifdef RODS_SERVER
        json pam_auth_agent_request(rsComm_t& comm, const json& req)
        {
            throw_if_key_is_missing_in_json(req, {"METHOD"});

            try {
                const auto& method = req.at("METHOD").get_ref<const std::string&>();

                if (method == "POST") {
                    return post(comm, req);
                }

                if (method == "GET") {
                    return get(comm, req);
                }

                if (method == "PUT") {
                    return put(comm, req);
                }

                if (method == "DELETE") {
                    return del(comm, req);
                }

                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                            fmt::runtime("[{}:{}] - invalid METHOD [{}]"),
                            __func__, __LINE__, itr->second));
            }
            catch (const json::exception& e) {
                THROW(SYS_LIBRARY_ERROR, fmt::format(
                      fmt::runtime("json error occurred [{}]"), e.what()));
            }
            catch (const std::exception& e) {
                //@todo error handling
                THROW(SYS_INTERNAL_ERR, fmt::format(
                      fmt::runtime("open_pam_handshake_session [{}]"), e.what()));
            }
        } // pam_auth_agent_request

#if 0
        json pam_auth_agent_response(rsComm_t& comm, const json& req)
        {
            throw_if_key_is_missing_in_json(req, {"user_name", "zone_name", "digest"});

            rodsServerHost_t* host;
            auto zone_name = req.at("zone_name").get<std::string>();
            int status = getAndConnRcatHostNoLogin(&comm, MASTER_RCAT, const_cast<char*>(zone_name.c_str()), &host);
            if ( status < 0 ) {
                THROW(status, "Connecting to rcat host failed.");
            }

            char* response = static_cast<char*>(malloc(RESPONSE_LEN + 1));
            std::memset(response, 0, RESPONSE_LEN + 1);
            const auto free_response = irods::at_scope_exit{[response] { free(response); }};

            response[RESPONSE_LEN] = 0;

            unsigned long out_len = RESPONSE_LEN;
            auto to_decode = req.at("digest").get<std::string>();
            auto err = base64_decode(reinterpret_cast<unsigned char*>(const_cast<char*>(to_decode.c_str())),
                                     to_decode.size(),
                                     reinterpret_cast<unsigned char*>(response),
                                     &out_len);
            if (err < 0) {
                THROW(err, "base64 decoding of digest failed.");
            }

            authCheckInp_t authCheckInp{};
            // this is nearly identical to the native auth plugin except for this part...
            authCheckInp.challenge = "dummy";
            authCheckInp.response = response;

            const std::string username = fmt::format("{}#{}", req.at("user_name").get<std::string>(), zone_name);
            authCheckInp.username = const_cast<char*>(username.data());

            authCheckOut_t* authCheckOut = nullptr;
            const auto free_auth_check_out = irods::at_scope_exit{
                [authCheckOut] {
                    if (authCheckOut) {
                        if (authCheckOut->serverResponse) {
                            free(authCheckOut->serverResponse);
                        }
                        free(authCheckOut);
                    }
                }
            };

            if (LOCAL_HOST == rodsServerHost->localFlag) {
                status = rsAuthCheck(&comm, &authCheckInp, &authCheckOut);
            }
            else {
                status = rcAuthCheck( rodsServerHost->conn, &authCheckInp, &authCheckOut );
                /* not likely we need this connection again */
                rcDisconnect( rodsServerHost->conn );
                rodsServerHost->conn = nullptr;
            }

            if (status < 0 || !authCheckOut) {
                THROW(status, "rcAuthCheck failed.");
            }

            /* have to modify privLevel if the icat is a foreign icat because
             * a local user in a foreign zone is not a local user in this zone
             * and vice versa for a remote user
             */
            if ( rodsServerHost->rcatEnabled == REMOTE_ICAT ) {
                /* proxy is easy because rodsServerHost is based on proxy user */
                if ( authCheckOut->privLevel == LOCAL_PRIV_USER_AUTH) {
                    authCheckOut->privLevel = REMOTE_PRIV_USER_AUTH;
                }
                else if ( authCheckOut->privLevel == LOCAL_USER_AUTH ) {
                    authCheckOut->privLevel = REMOTE_USER_AUTH;
                }

                /* adjust client user */
                if ( 0 == strcmp(comm.proxyUser.userName, comm.clientUser.userName ) ) {
                    authCheckOut->clientPrivLevel = authCheckOut->privLevel;
                }
                else {
                    zoneInfo_t *tmpZoneInfo;
                    status = getLocalZoneInfo( &tmpZoneInfo );
                    if ( status < 0 ) {
                        THROW(status, "getLocalZoneInfo failed.");
                    }

                    if ( 0 == strcmp( tmpZoneInfo->zoneName, comm.clientUser.rodsZone ) ) {
                        /* client is from local zone */
                        if ( authCheckOut->clientPrivLevel == REMOTE_PRIV_USER_AUTH ) {
                            authCheckOut->clientPrivLevel = LOCAL_PRIV_USER_AUTH;
                        }
                        else if ( authCheckOut->clientPrivLevel == REMOTE_USER_AUTH ) {
                            authCheckOut->clientPrivLevel = LOCAL_USER_AUTH;
                        }
                    }
                    else {
                        /* client is from remote zone */
                        if ( authCheckOut->clientPrivLevel == LOCAL_PRIV_USER_AUTH ) {
                            authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                        }
                        else if ( authCheckOut->clientPrivLevel == LOCAL_USER_AUTH ) {
                            authCheckOut->clientPrivLevel = REMOTE_USER_AUTH;
                        }
                    }
                }
            }
            else if ( 0 == strcmp(comm.proxyUser.userName,  comm.clientUser.userName ) ) {
                authCheckOut->clientPrivLevel = authCheckOut->privLevel;
            }

            irods::throw_on_insufficient_privilege_for_proxy_user(comm, authCheckOut->privLevel);

            if ( strcmp(comm.proxyUser.userName, comm.clientUser.userName ) != 0 ) {
                comm.proxyUser.authInfo.authFlag = authCheckOut->privLevel;
                comm.clientUser.authInfo.authFlag = authCheckOut->clientPrivLevel;
            }
            else {          /* proxyUser and clientUser are the same */
                comm.proxyUser.authInfo.authFlag =
                    comm.clientUser.authInfo.authFlag = authCheckOut->privLevel;
            }

            return resp;
        } // pam_auth_agent_response
#endif // 0
#endif // #ifdef RODS_SERVER
    }; // pam_authentication
}

extern "C"
irods::pam_authentication* plugin_factory(const std::string&, const std::string&)
{
    return new irods::pam_authentication{};
}
