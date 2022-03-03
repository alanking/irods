#ifndef IRODS_AUTHENTICATION_PLUGIN_FRAMEWORK_HPP
#define IRODS_AUTHENTICATION_PLUGIN_FRAMEWORK_HPP

#include "irods/authenticate.h"
#include "irods/getRodsEnv.h"
#include "irods/irods_auth_constants.hpp"
#include "irods/irods_exception.hpp"
#include "irods/irods_load_plugin.hpp"
#include "irods/irods_plugin_base.hpp"
#include "irods/rcConnect.h"
#include "irods/rodsErrorTable.h"

#include <boost/any.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <string>

/// \file

using json = nlohmann::json;

namespace irods::experimental::auth
{
    static const std::string flow_complete{"authentication_flow_complete"};
    static const std::string next_operation{"next_operation"};

    /// \brief Pure virtual base class for authentication plugin implementations.
    ///
    /// \since 4.3.0
    class authentication_base : public irods::plugin_base
    {
    public:
        #define OPERATION(C, F) std::function<json(C&, const json&)>([&](C& c, const json& j) -> json {return F(c, j);})

        /// \brief Constructor for the authentication plugin pure virtual base class.
        ///
        /// \since 4.3.0
        authentication_base()
            : plugin_base{"authentication_framework_plugin", "empty_context_string"}
        {
            add_operation(AUTH_CLIENT_START, OPERATION(RcComm, auth_client_start));
        } // ctor

        /// Pure virtual method which all authentication plugins must implement.
        ///
        /// \since 4.3.0
        virtual json auth_client_start(RcComm& _comm, const json& req) = 0;

        /// \brief Add the operation captured in \p f to the plugin's operation map at key \p n.
        ///
        /// \param[in] n Key with which the operation will be discovered in the operation map.
        /// \param[in] f Function object which implements the operation being added.
        ///
        /// \throws irods::exception If \p n is empty or already exists in the operation map.
        ///
        /// \since 4.3.0
        template<typename RxComm>
        void add_operation(const std::string& n, std::function<json(RxComm&, const json&)> f)
        {
            if(n.empty()) {
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format("operation name is empty [{}]", n));
            }

            if (operations_.has_entry(n)) {
                THROW(SYS_INTERNAL_ERR, fmt::format("operation already exists [{}]", n));
            }

            operations_[n] = f;
        } // add_operation

        /// \brief Invoke the operation at key \p n.
        ///
        /// param[in/out] _comm iRODS communication object.
        /// param[in] n Key associated with the operation being invoked.
        /// param[in] req JSON payload including the data for the operation.
        ///
        /// \throws irods::exception If there is no key \p n in the operations map.
        ///
        /// \returns JSON object representing the result of the operation.
        ///
        /// \since 4.3.0
        template<typename RxComm>
        json call(RxComm& _comm, const std::string& n, const json& req)
        {
            if (!operations_.has_entry(n)) {
                THROW(SYS_INVALID_INPUT_PARAM,
                      fmt::format("call operation :: missing operation[{}]", n));
            }

            using fcn_t = std::function<json(RxComm&, const json&)>;
            auto op = boost::any_cast<fcn_t&>(operations_[n]);

            return op(_comm, req);
        } // call
    }; // class authentication_base

    /// \brief Resolve the authentication plugin with \p scheme of type "client" or "server".
    ///
    /// \param[in] _scheme The authentication scheme whose plugin is being loaded.
    /// \param[in] _type A string which indicates the type of the plugin ("client" or "server").
    ///
    /// \throws irods::exception If loading the plugin is unsuccessful.
    ///
    /// \returns The authentication plugin object (descendant of \p authentication_base).
    ///
    /// \since 4.3.0
    auto resolve_authentication_plugin(const std::string& _scheme, const std::string& _type)
    {
        using plugin_type = authentication_base;

        std::string scheme = _scheme;
        std::transform(scheme.begin(), scheme.end(), scheme.begin(), ::tolower);

        const std::string name = fmt::format("irods_auth_plugin-{}_{}", scheme, _type);

        plugin_type* plugin{};
        auto err = irods::load_plugin<plugin_type>(plugin,
                                                   name,
                                                   irods::PLUGIN_TYPE_AUTHENTICATION,
                                                   name,
                                                   "empty_context");
        if(!err.ok()) {
            THROW(err.code(), err.result());
        }

        return plugin;
    } // resolve_plugin

    /// \brief Authenticate the client indicated by \p _comm with scheme \p env.
    ///
    /// \parblock
    /// Starting with the operation indicated by \p irods::AUTH_CLIENT_START in the operation
    /// map of the authentication plugin, this function loops until the response from an
    /// invoked operation in the plugin returns a "next_operation" of \p auth::flow_complete.
    /// At that time, \p _comm.loggedIn should be set to 1 (or anything other than 0) and the
    /// client is considered authenticated.
    ///
    /// This function acts as the interface to the authentication plugins much like
    /// \p clientLogin was the interface for the legacy authentication plugins.
    /// \endparblock
    ///
    /// \param[in/out] _comm iRODS communication object.
    /// \param[in] _env Environment object from which the authentication scheme is retrieved.
    /// \param[in] _ctx JSON object which includes information for the authentication plugin.
    ///
    /// \throws irods::exception \parblock
    /// - If the authentication plugin cannot be resolved
    /// - If an operation fails to set "next_operation" to a non-empty string in its response
    /// - If the flow is completed with \p !_comm.loggedIn
    /// \endparblock
    ///
    /// \since 4.3.0
    void authenticate_client(RcComm& _comm, const RodsEnvironment& _env, const json& _ctx)
    {
        std::string scheme = _env.rodsAuthScheme;

        auto auth = resolve_authentication_plugin(scheme, "client");

        const std::string* next_operation = &irods::AUTH_CLIENT_START;

        json req{}, resp{};

        req["scheme"] = scheme;
        req[auth::next_operation] = *next_operation;

        for (const auto& [k, v] : _ctx.items()) {
            req[k] = v;
        }

        while (true) {
            resp = auth->call(_comm, *next_operation, req);

            if (_comm.loggedIn) {
                break;
            }

            if (!resp.contains(auth::next_operation)) {
                THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                      "authentication request missing [{}] parameter",
                      auth::next_operation));
            }

            next_operation = resp.at(auth::next_operation).get_ptr<std::string*>();
            if (next_operation->empty() || auth::flow_complete == *next_operation) {
                THROW(CAT_INVALID_AUTHENTICATION,
                      "authentication flow completed without success");
            }

            req = resp;
        }
    } // authenticate_client
} // namespace irods::experimental::auth

#endif // IRODS_AUTHENTICATION_PLUGIN_FRAMEWORK_HPP
