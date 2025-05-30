#include "irods/plugins/api/api_plugin_number.h"
#include "irods/client_api_allowlist.hpp"
#include "irods/fileDriver.hpp"
#include "irods/irods_configuration_keywords.hpp"
#include "irods/json_deserialization.hpp"
#include "irods/rcConnect.h"
#include "irods/rcMisc.h"
#include "irods/rodsDef.h"
#include "irods/rodsErrorTable.h"
#include "irods/rodsPackInstruct.h"

#include "irods/apiHandler.hpp"

#include <functional>
#include <stdexcept>

#ifdef RODS_SERVER

//
// Server-side Implementation
//

#include "irods/data_object_finalize.h"

#include "irods/catalog.hpp"
#include "irods/catalog_utilities.hpp"
#include "irods/icatHighLevelRoutines.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_exception.hpp"
#include "irods/irods_get_full_path_for_config_file.hpp"
#include "irods/irods_get_l1desc.hpp"
#include "irods/irods_logger.hpp"
#include "irods/irods_re_serialization.hpp"
#include "irods/irods_resource_manager.hpp"
#include "irods/irods_rs_comm_query.hpp"
#include "irods/irods_server_api_call.hpp"
#include "irods/irods_stacktrace.hpp"
#include "irods/miscServerFunct.hpp"
#include "irods/objDesc.hpp"
#include "irods/rodsConnect.h"
#include "irods/server_utilities.hpp"

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include "irods/filesystem.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "irods/data_object_proxy.hpp"

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <nanodbc/nanodbc.h>

#include <cstdlib>
#include <string>
#include <string_view>
#include <tuple>
#include <chrono>
#include <system_error>

extern irods::resource_manager resc_mgr;

namespace
{
    // clang-format off
    namespace fs  = irods::experimental::filesystem;
    namespace ic  = irods::experimental::catalog;
    namespace id  = irods::experimental::data_object;
    namespace log = irods::experimental::log;

    using json      = nlohmann::json;
    using operation = std::function<int(RsComm*, BytesBuf*, BytesBuf**)>;
    // clang-format on

    constexpr inline auto database_updated = true;

    auto make_error_object(const std::string_view _error_msg = "", const bool _database_updated = false) -> json
    {
        return json{{"error_message", _error_msg},
                    {"database_updated", _database_updated}};
    } // make_error_object

    auto call_data_object_finalize(
        irods::api_entry* _api,
        RsComm* _comm,
        BytesBuf* _input,
        BytesBuf** _output) -> int
    {
        return _api->call_handler<BytesBuf*, BytesBuf**>(_comm, _input, _output);
    } // call_data_object_finalize

    auto split_before_and_after_info(const json& _json_list) -> std::tuple<id::json_repr_t, id::json_repr_t>
    {
        id::json_repr_t before;
        id::json_repr_t after;

        for (const auto& i : _json_list) {
            const auto* b = &i.at("before");
            const auto* a = &i.at("after");
            before.push_back(b);
            after.push_back(a);
        }

        return {before, after};
    } // split_before_and_after_info

    auto set_file_object_keywords(const json& _src, irods::file_object_ptr _obj) -> void
    {
        irods::log(LOG_DEBUG9, fmt::format("[{}:{}] - src:[{}]", __FUNCTION__, __LINE__, _src.dump()));

        const auto src = irods::experimental::make_key_value_proxy(*irods::to_key_value_pair(_src));
        const auto free_src = irods::at_scope_exit{[&src]
            {
                clearKeyVal(src.get());
                std::free(src.get());
            }
        };

        // Template argument deduction is ambiguous here because cond_input() is overloaded
        auto out = irods::experimental::make_key_value_proxy<KeyValPair>(_obj->cond_input());

        // TODO: just make a make_key_value_proxy which accepts a std::map/json structure...
        if (src.contains(ADMIN_KW)) {
            out[ADMIN_KW] = src.at(ADMIN_KW);
        }
        if (src.contains(IN_PDMO_KW)) {
            _obj->in_pdmo(src.at(IN_PDMO_KW).value().data());
            out[IN_PDMO_KW] = src.at(IN_PDMO_KW);
        }
        if (src.contains(OPEN_TYPE_KW)) {
            out[OPEN_TYPE_KW] = src.at(OPEN_TYPE_KW);
        }
        if (src.contains(SYNC_OBJ_KW)) {
            out[SYNC_OBJ_KW] = src.at(SYNC_OBJ_KW);
        }
        if (src.contains(REPL_STATUS_KW)) {
            out[REPL_STATUS_KW] = src.at(REPL_STATUS_KW);
        }
        if (src.contains(IN_REPL_KW)) {
            out[IN_REPL_KW] = src.at(IN_REPL_KW);
        }
    } // set_file_object_keywords

    auto invoke_file_modified(RsComm& _comm, const std::string_view _logical_path, json& _replicas) -> int
    {
        try {
            for (auto&& replica : _replicas) {
                irods::log(LOG_DEBUG9, fmt::format("[{}:{}] - replica:[{}]", __FUNCTION__, __LINE__, replica.dump()));

                if (replica.contains(FILE_MODIFIED_KW)) {
                    // There are two ways to get the irods::file_object required for the fileModified interface:
                    //   1. data_object_finalize takes a logical_path key which describes the full logical path.
                    //      If the logical_path is not supplied, the information must be fetched from the catalog.
                    //
                    //   2. If the logical_path is supplied, the query mentioned above can be avoided. Combined
                    //      with the information in R_DATA_MAIN, this information is sufficient to construct
                    //      the file_object.
                    irods::file_object_ptr obj;
                    if (_logical_path.empty()) {
                        obj = irods::file_object_factory(_comm, std::stoll(replica.at("before").at("data_id").get<std::string>()));
                    }
                    else {
                        auto [before, after] = split_before_and_after_info(_replicas);
                        obj = irods::file_object_factory(_comm, _logical_path, after);
                    }

                    const auto leaf_resource_id = std::stoll(replica.at("after").at("resc_id").get<std::string>());
                    obj->resc_hier(resc_mgr.leaf_id_to_hier(leaf_resource_id));

                    set_file_object_keywords(replica.at(FILE_MODIFIED_KW), obj);

                    // Even if fileModified is requested for this replica, do not trigger it if:
                    //   - IN_REPL_KW is set - this means this is already a fileModified operation
                    //   - The open type is read-only - read-only means nothing has been modified
                    const auto obj_cond_input = irods::experimental::make_key_value_proxy(obj->cond_input());
                    if (obj_cond_input.contains(IN_REPL_KW) ||
                        (obj_cond_input.contains(OPEN_TYPE_KW) &&
                         obj_cond_input.at(OPEN_TYPE_KW).value() == std::to_string(OPEN_FOR_READ_TYPE))) {
                        return 0;
                    }

                    if (const auto ret = fileModified(&_comm, obj); !ret.ok()) {
                        irods::log(LOG_ERROR, fmt::format(
                            "[{}] - failed to signal the resource that [{}] on [{}] was modified",
                            __FUNCTION__, obj->logical_path(), obj->resc_hier()));

                        return ret.code();
                    }

                    irods::log(LOG_DEBUG, fmt::format(
                        "[{}:{}] - fileModified complete,obj:[{}],hier:[{}]",
                        __FUNCTION__, __LINE__, obj->logical_path(), obj->resc_hier()));

                    // TODO: consider more than one?
                    return 0;
                }
            }

            irods::log(LOG_DEBUG, fmt::format(
                "[{}:{}] - no fileModified",
                __FUNCTION__, __LINE__));

            return 0;
        }
        catch (const irods::exception& e) {
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.client_display_what()));
            return e.code();
        }
        catch (const std::exception& e) {
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.what()));
            return SYS_INTERNAL_ERR;
        }
        catch (...) {
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - unknown error occurred", __FUNCTION__, __LINE__));
            return SYS_UNKNOWN_ERROR;
        }
    } // invoke_file_modified

    auto finalize(
        RsComm& _comm,
        json& _replicas,
        const std::string_view _bytes_written,
        const bool _admin_operation,
        BytesBuf** _output) -> int
    {
        // Establish connection with the database for use with nanodbc.
        // A connection with the database is already established via the
        // RsComm, but this allows us to atomically update the database
        // without the complicated machinery of the existing database plugin.
        std::string db_instance_name;
        nanodbc::connection db_conn;
        try {
            std::tie(db_instance_name, db_conn) = ic::new_database_connection();
        }
        catch (const std::exception& e) {
            const auto msg = e.what();

            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, msg));

            *_output = irods::to_bytes_buffer(make_error_object(msg).dump());

            return SYS_CONFIG_FILE_ERR;
        }

        try {
            // This section will perform permissions checks and update ticket information
            // only if not running in privileged mode. This matches the behavior of
            // the mod_data_obj_meta database operation.
            const auto data_id = std::stoll(_replicas.front().at("before").at("data_id").get<std::string>());

            const auto bytes_written = !_bytes_written.empty() ? std::stoll(_bytes_written.data()) : 0;

            if (!_admin_operation) {
                // If the caller indicates that bytes have been written (equivalent
                // to updating the size), the information for any existing session
                // ticket should be updated to reflect the new write byte count.
                if (bytes_written) {
                    if (const auto ec = chl_update_ticket_write_byte_count(_comm, data_id, bytes_written); ec != 0) {
                        const auto msg = fmt::format("failed to update write_bytes_count on ticket [data_id=[{}]]", data_id);

                        irods::log(LOG_NOTICE, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, msg));

                        *_output = irods::to_bytes_buffer(make_error_object(msg).dump());

                        return ec;
                    }
                }

                // Make sure the user has permission to modify this data object
                // before proceeding. This database operation also updates ticket
                // information and checks to make sure the limit for write byte
                // count has not been exceeded.
                if (const auto ec = chl_check_permission_to_modify_data_object(_comm, data_id); ec != 0) {
                    const auto msg = fmt::format("user not allowed to modify data object [data id=[{}]]", data_id);

                    irods::log(LOG_NOTICE, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, msg));

                    *_output = irods::to_bytes_buffer(make_error_object(msg).dump());

                    return ec;
                }
            }
        }
        catch (const json::exception& e) {
            const auto msg = fmt::format("json exception occurred [{}]", e.what());

            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, msg));

            *_output = irods::to_bytes_buffer(make_error_object(msg).dump());

            return SYS_LIBRARY_ERROR;
        }

        const auto ec = chl_data_object_finalize(_comm, json{{"replicas", _replicas}}.dump().c_str());

        if (ec < 0) {
            *_output = irods::to_bytes_buffer(make_error_object("failed to update catalog").dump());
        }

        return ec;
    } // finalize

    auto rs_data_object_finalize(
        RsComm* _comm,
        BytesBuf* _input,
        BytesBuf** _output) -> int
    {
        // Parses out the JSON from the input
        json input;
        try {
            input = json::parse(std::string(static_cast<const char*>(_input->buf), _input->len));
            log::database::debug("json input:[{}]", input.dump());
        }
        catch (const json::parse_error& e) {
            const std::string_view msg = e.what();

            log::api::error({{"log_message", fmt::format(
                              "[{}:{}] - Failed to parse input into JSON",
                              __FUNCTION__, __LINE__)},
                             {"error_message", msg.data()}});

            *_output = irods::to_bytes_buffer(make_error_object(msg).dump());

            return INPUT_ARG_NOT_WELL_FORMED_ERR;
        }

        // The following section separates out the relevant pieces from the input.
        // These include whether or not the operation should be run in privileged
        // mode, the list of replicas for the data object being finalized, and
        // whether or not file_modified should be triggered.
        json replicas;
        bool trigger_file_modified = false;
        bool admin_operation = false;
        try {
            if (input.contains("irods_admin") && input.at("irods_admin").get<bool>()) {
                if (!irods::is_privileged_client(*_comm)) {
                    const auto msg = "user is not authorized to use the admin keyword";

                    *_output = irods::to_bytes_buffer(make_error_object(msg).dump());

                    irods::log(LOG_WARNING, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, msg));

                    return CAT_INSUFFICIENT_PRIVILEGE_LEVEL;
                }

                admin_operation = true;
            }

            trigger_file_modified = input.contains("trigger_file_modified") && input.at("trigger_file_modified").get<bool>();

            replicas = input.at("replicas");
        }
        catch (const json::type_error& e) {
            *_output = irods::to_bytes_buffer(make_error_object(e.what()).dump());

            return SYS_INVALID_INPUT_PARAM;
        }
        catch (const std::exception& e) {
            *_output = irods::to_bytes_buffer(make_error_object(e.what()).dump());

            return SYS_INVALID_INPUT_PARAM;
        }

        // Update the database here, redirecting if necessary.
        try {
            if (!ic::connected_to_catalog_provider(*_comm)) {
                // If not already connected to the catalog service provider, redirect and execute the
                // database update for finalize. If no errors are returned, execution will continue on
                // to perform the file_modified logic here.
                irods::log(LOG_DEBUG8, "Redirecting request to catalog service provider ...");

                auto* host_info = ic::redirect_to_catalog_provider(*_comm);

                // Explicitly set trigger_file_modified to false here. The file_modified logic should be
                // executing on this machine, not the catalog service provider to which the connection is
                // redirecting here.
                input["trigger_file_modified"] = false;

                char* json_output = nullptr;

                const auto ec = rc_data_object_finalize(host_info->conn, input.dump().data(), &json_output);
                *_output = irods::to_bytes_buffer(json_output);
                if (ec < 0) {
                    return ec;
                }
            }
            else {
                ic::throw_if_catalog_provider_service_role_is_invalid();

                const std::string bytes_written = input.contains("bytes_written") ? input.at("bytes_written").get<std::string>() : "";

                // The finalize call here will set the appropriate errors in the output variable.
                if (const auto ec = finalize(*_comm, replicas, bytes_written, admin_operation, _output); ec < 0) {
                    return ec;
                }
            }
        }
        catch (const irods::exception& e) {
            const std::string_view msg = e.client_display_what();

            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, msg));

            *_output = irods::to_bytes_buffer(make_error_object(msg).dump());

            return e.code();
        }

        // If the update was successful and file modified is not supposed to be
        // triggered, then we can return with success here.
        if (!trigger_file_modified) {
            *_output = irods::to_bytes_buffer(make_error_object("", database_updated).dump());
            return 0;
        }

        try {
            const std::string logical_path = input.contains("logical_path") ? input.at("logical_path").get<std::string>() : "";
            const auto ec = invoke_file_modified(*_comm, logical_path, replicas);

            if (ec < 0) {
                const auto msg = "error occurred during file_modified operation";

                *_output = irods::to_bytes_buffer(make_error_object(msg, database_updated).dump());

                return ec;
            }

            *_output = irods::to_bytes_buffer(make_error_object("", database_updated).dump());
            return ec;
        }
        catch (const irods::exception& e) {
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.client_display_what()));

            const auto err = make_error_object(e.client_display_what(), database_updated);

            *_output = irods::to_bytes_buffer(err.dump());

            return e.code();
        }
    } // rs_data_object_finalize

    const operation op = rs_data_object_finalize;
    #define CALL_DATA_OBJECT_FINALIZE call_data_object_finalize
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace {
    using operation = std::function<int(RsComm*, BytesBuf*, BytesBuf**)>;
    const operation op{};
    #define CALL_DATA_OBJECT_FINALIZE nullptr
} // anonymous namespace

#endif // RODS_SERVER

// The plugin factory function must always be defined.
extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> irods::api_entry*
{
    // clang-format off
    irods::apidef_t def{
        DATA_OBJECT_FINALIZE_APN,   // API number
        RODS_API_VERSION,           // API version
        REMOTE_USER_AUTH,           // Client auth
        REMOTE_USER_AUTH,           // Proxy auth
        "BinBytesBuf_PI", 0,        // In PI / bs flag
        "BinBytesBuf_PI", 0,        // Out PI / bs flag
        op,                         // Operation
        "data_object_finalize",     // Operation name
        clearBytesBuffer,           // clear input function
        clearBytesBuffer,           // clear output function
        (funcPtr) CALL_DATA_OBJECT_FINALIZE
    };
    // clang-format on

    auto* api = new irods::api_entry{def};

    api->in_pack_key = "BinBytesBuf_PI";
    api->in_pack_value = BytesBuf_PI;

    api->out_pack_key = "BinBytesBuf_PI";
    api->out_pack_value = BytesBuf_PI;

    return api;
} // plugin_factory
