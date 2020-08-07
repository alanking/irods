#include "api_plugin_number.h"
#include "irods_configuration_keywords.hpp"
#include "rodsDef.h"
#include "rcConnect.h"
#include "rodsErrorTable.h"
#include "rodsPackInstruct.h"
#include "client_api_whitelist.hpp"

#include "apiHandler.hpp"

#include <functional>
#include <stdexcept>

#ifdef RODS_SERVER

//
// Server-side Implementation
//

#include "finalize_data_object.h"

#include "catalog.hpp"
#include "catalog_utilities.hpp"
#include "irods_exception.hpp"
#include "irods_get_full_path_for_config_file.hpp"
#include "irods_get_l1desc.hpp"
#include "irods_logger.hpp"
#include "irods_query.hpp"
#include "irods_re_serialization.hpp"
#include "irods_rs_comm_query.hpp"
#include "irods_server_api_call.hpp"
#include "irods_stacktrace.hpp"
#include "miscServerFunct.hpp"
#include "objDesc.hpp"
#include "rodsConnect.h"

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include "filesystem.hpp"

#include "json.hpp"
#include "fmt/format.h"
#include "nanodbc/nanodbc.h"

#include <cstdlib>
#include <string>
#include <string_view>
#include <tuple>
#include <chrono>
#include <system_error>

namespace {
    // clang-format off
    namespace fs    = irods::experimental::filesystem;
    namespace ic    = irods::experimental::catalog;

    using log       = irods::experimental::log;
    using json      = nlohmann::json;
    using operation = std::function<int(rsComm_t*, bytesBuf_t*, bytesBuf_t**)>;
    // clang-format on

    auto call_finalize_data_object(
        irods::api_entry* _api,
        rsComm_t* _comm,
        bytesBuf_t* _input,
        bytesBuf_t** _output) -> int
    {
        return _api->call_handler<bytesBuf_t*, bytesBuf_t**>(_comm, _input, _output);
    } // call_finalize_data_object

    auto set_replica_state(
        nanodbc::connection& _db_conn,
        std::string_view _data_id,
        const json& _before,
        const json& _after) -> void
    {
        nanodbc::statement statement{_db_conn};

        log::database::debug("before:{}", _before.dump());
        log::database::debug("after:{}", _after.dump());

        // prepare SQL statement string
        const auto& cmap = ic::data_objects::column_mapping_operators;

        std::string s{"update R_DATA_MAIN set"};

        for (auto&& c : cmap) {
            s += fmt::format(" {} = ?,", c.first);
        }
        s.pop_back();

        s += " where data_id = ? and resc_id = ?";

        log::database::debug("statement:[{}]", s);

        prepare(statement, s);

        std::vector<ic::bind_type> bind_values;
        bind_values.reserve(cmap.size());

        // apply bind variables
        std::size_t index = 0;
        for (auto&& c : cmap) {
            const auto& key = c.first;

            const auto& bind_fcn = c.second;

            ic::bind_parameters bp{statement, index, _after, key, bind_values};

            bind_fcn(bp);

            index++;
        }

        const auto data_id = std::stoul(_data_id.data());
        log::database::trace("binding data_id:[{}] at [{}]", data_id, index);
        statement.bind(index++, &data_id);

        const auto resc_id = std::stoul(_before.at("resc_id").get<std::string>());
        log::database::trace("binding resc_id:[{}] at [{}]", resc_id, index);
        statement.bind(index, &resc_id);

        execute(statement);
    } // set_replica_state

    auto set_data_object_state(
        nanodbc::connection& _db_conn,
        nanodbc::transaction& _trans,
        std::string_view _data_id,
        const json& _replicas) -> void
    {
        try {
            for (auto&& r : _replicas) {
                set_replica_state(_db_conn, _data_id, r.at("before"), r.at("after"));
            }

            log::database::debug("committing transaction");
            _trans.commit();
        }
        catch (const nanodbc::database_error& e) {
            THROW(SYS_LIBRARY_ERROR, e.what());
        }
        catch (const std::exception& e) {
            THROW(SYS_INTERNAL_ERR, e.what());
        }
    } // set_data_object_state

    auto rs_finalize_data_object(
        rsComm_t* _comm,
        bytesBuf_t* _input,
        bytesBuf_t** _output) -> int
    {
        // TODO: redirect to catalog provider

        json input;

        try {
            input = json::parse(std::string(static_cast<const char*>(_input->buf), _input->len));
            log::database::debug("input:[{}]", input.dump());
        }
        catch (const json::parse_error& e) {
            log::api::error({{"log_message", "Failed to parse input into JSON"},
                             {"error_message", e.what()}});

            //const auto err_info = make_error_object(json{}, 0, e.what());
            //*_output = to_bytes_buffer(err_info.dump());

            return INPUT_ARG_NOT_WELL_FORMED_ERR;
        }

        std::string data_id;
        json replicas;

        try {
            data_id = input.at("data_id").get<std::string>();
            replicas = input.at("replicas");
        }
        catch (const std::exception& e) {
            //*_output = to_bytes_buffer(make_error_object(json{}, 0, e.what()).dump());
            return SYS_INVALID_INPUT_PARAM;
        }

        nanodbc::connection db_conn;

        try {
            std::tie(std::ignore, db_conn) = ic::new_database_connection();
        }
        catch (const std::exception& e) {
            log::database::error(e.what());
            return SYS_CONFIG_FILE_ERR;
        }

        return ic::execute_transaction(db_conn, [&](auto& _trans) -> int
        {
            try {
                set_data_object_state(db_conn, _trans, data_id, replicas);
                return 0;
            }
            catch (const irods::exception& e) {
                log::database::error(e.what());
                return e.code();
            }
        });
    } // rs_finalize_data_object

    const operation op = rs_finalize_data_object;
    #define CALL_FINALIZE_DATA_OBJECT call_finalize_data_object
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace {
    using operation = std::function<int(rsComm_t*, bytesBuf_t*, bytesBuf_t**)>;
    const operation op{};
    #define CALL_FINALIZE_DATA_OBJECT nullptr
} // anonymous namespace

#endif // RODS_SERVER

// The plugin factory function must always be defined.
extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> irods::api_entry*
{
#ifdef RODS_SERVER
    irods::client_api_whitelist::instance().add(FINALIZE_DATA_OBJECT_APN);
#endif // RODS_SERVER

    // clang-format off
    irods::apidef_t def{FINALIZE_DATA_OBJECT_APN,                   // API number
                        RODS_API_VERSION,                           // API version
                        NO_USER_AUTH,                               // Client auth
                        NO_USER_AUTH,                               // Proxy auth
                        "BytesBuf_PI", 0,                           // In PI / bs flag
                        "BytesBuf_PI", 0,                           // Out PI / bs flag
                        op,                                         // Operation
                        "finalize_data_object",                     // Operation name
                        nullptr,                                    // Null clear function
                        (funcPtr) CALL_FINALIZE_DATA_OBJECT};
    // clang-format on

    auto* api = new irods::api_entry{def};

    api->in_pack_key = "BytesBuf_PI";
    api->in_pack_value = BytesBuf_PI;

    api->out_pack_key = "BytesBuf_PI";
    api->out_pack_value = BytesBuf_PI;

    return api;
}

