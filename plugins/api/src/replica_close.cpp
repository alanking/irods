#include "api_plugin_number.h"
#include "rodsDef.h"
#include "rcConnect.h"
#include "rodsPackInstruct.h"
#include "client_api_whitelist.hpp"

#include "apiHandler.hpp"

#include <functional>

#ifdef RODS_SERVER

//
// Server-side Implementation
//

#include "replica_close.h"

#include "objDesc.hpp"
#include "rsFileClose.hpp"
#include "irods_server_api_call.hpp"
#include "irods_re_serialization.hpp"
#include "irods_resource_backport.hpp"
#include "irods_configuration_keywords.hpp"
#include "irods_query.hpp"
#include "irods_exception.hpp"
#include "replica_access_table.hpp"
#include "irods_logger.hpp"

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include "filesystem.hpp"
#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "replica.hpp"

#include "replica_state_table.hpp"
#include "rs_data_object_finalize.hpp"

#include "fmt/format.h"
#include "json.hpp"

#include <cstring>
#include <string>
#include <string_view>
#include <tuple>
#include <chrono>
#include <optional>

#include <sys/types.h>
#include <unistd.h>

namespace
{
    namespace ix = irods::experimental;
    namespace fs = irods::experimental::filesystem;
    namespace replica = irods::experimental::replica;
    namespace data_object = irods::experimental::data_object;

    // clang-format off
    using data_object_proxy   = irods::experimental::data_object::data_object_proxy<DataObjInfo>;
    using json                = nlohmann::json;
    using log                 = ix::log;
    using operation           = std::function<int(RsComm*, bytesBuf_t*)>;
    using replica_state_table = irods::experimental::replica_state_table;
    // clang-format on

    //
    // Function Prototypes
    //

    auto call_replica_close(irods::api_entry*, RsComm*, bytesBuf_t*) -> int;

    auto is_input_valid(const bytesBuf_t*) -> std::tuple<bool, std::string>;

    auto parse_json(const bytesBuf_t& _bbuf) -> std::tuple<int, json>;

    auto get_file_descriptor_index(const json& _json) -> std::tuple<int, int>;

    auto rs_replica_close(RsComm* _comm, bytesBuf_t* _input) -> int;

    auto close_physical_object(RsComm& _comm, int _l3desc_index) -> int;

    auto update_replica_size_and_status(RsComm& _comm, const l1desc_t& _l1desc) -> void;

    auto update_replica_size(RsComm& _comm, const l1desc_t& _l1desc) -> void;

    auto update_replica_status(RsComm& _comm, const l1desc_t& _l1desc, const int _new_status) -> void;

    auto update_replica_checksum(RsComm& _comm, const l1desc_t& _l1desc) -> void;

    auto free_l1_descriptor(int _l1desc_index) -> int;

    auto get_data_object_state(const l1desc_t& _l1desc, const replica_state_table::state_type& _state) -> replica_state_table::data_object_handle;

    auto update_catalog(RsComm& _comm) -> void;

    //
    // Function Implementations
    //

    auto call_replica_close(irods::api_entry* _api, RsComm* _comm, bytesBuf_t* _input) -> int
    {
        return _api->call_handler<bytesBuf_t*>(_comm, _input);
    }

    auto is_input_valid(const bytesBuf_t* _input) -> std::tuple<bool, std::string>
    {
        if (!_input) {
            return {false, "Missing logical path"};
        }

        if (_input->len <= 0) {
            return {false, "Length of buffer must be greater than zero"};
        }

        if (!_input->buf) {
            return {false, "Missing input buffer"};
        }

        return {true, ""};
    }

    auto parse_json(const bytesBuf_t& _bbuf) -> std::tuple<int, json>
    {
        try {
            std::string_view json_string(static_cast<const char*>(_bbuf.buf), _bbuf.len);
            log::api::trace("Parsing string into JSON ... [string={}]", json_string);
            return {0, json::parse(json_string)};
        }
        catch (const json::parse_error& e) {
            return {SYS_INTERNAL_ERR, {}};
        }
    }

    auto get_file_descriptor_index(const json& _json) -> std::tuple<int, int>
    {
        try {
            return {0, _json.at("fd").get<int>()};
        }
        catch (const json::type_error& e) {
            return {SYS_INTERNAL_ERR, -1};
        }
    }

    auto close_physical_object(RsComm& _comm, int _l3desc_index) -> int
    {
        fileCloseInp_t input{};
        input.fileInx = _l3desc_index;
        return rsFileClose(&_comm, &input);
    }

    auto update_replica_size_and_status(RsComm& _comm, const l1desc_t& _l1desc) -> void
    {
        auto [after, after_lm] = get_data_object_state(_l1desc, replica_state_table::state_type::after);
        auto replica = *data_object::find_replica(after, _l1desc.dataObjInfo->rescHier);

        const auto size_on_disk = replica::get_replica_size_from_storage(
            _comm,
            _l1desc.dataObjInfo->objPath,
            _l1desc.dataObjInfo->rescHier,
            _l1desc.dataObjInfo->filePath);

        // If the size of the replica has changed since opening it, then update the size.
        if (_l1desc.dataObjInfo->dataSize != size_on_disk) {
            replica.size(size_on_disk);
            replica.mtime(SET_TIME_TO_NOW_KW);
            replica.replica_status(GOOD_REPLICA);
        }
        // If the contents of the replica has changed, then update the last modified timestamp.
        else if (_l1desc.bytesWritten > 0) {
            replica.mtime(SET_TIME_TO_NOW_KW);
            replica.replica_status(GOOD_REPLICA);
        }
        // If this is a new replica and the size is supposed to be 0, mark it as good.
        else if (_l1desc.dataObjInp->openFlags & O_CREAT && 0 == _l1desc.dataObjInfo->dataSize) {
            replica.replica_status(GOOD_REPLICA);
        }
        // If the contents have not changed, use the previous replica status.
        else {
            auto [before, before_lm] = get_data_object_state(_l1desc, replica_state_table::state_type::before);
            auto before_replica = *data_object::find_replica(before, _l1desc.dataObjInfo->rescHier);
            replica.replica_status(before_replica.replica_status());
        }

        replica_state_table::instance().set_data_object_state(_l1desc.dataObjInfo->objPath, after, replica_state_table::state_type::after);
    } // update_replica_size_and_status

    auto update_replica_size(RsComm& _comm, const l1desc_t& _l1desc) -> void
    {
        auto [after, after_lm] = get_data_object_state(_l1desc, replica_state_table::state_type::after);
        auto replica = *data_object::find_replica(after, _l1desc.dataObjInfo->rescHier);

        const auto size_on_disk = replica::get_replica_size_from_storage(
            _comm,
            _l1desc.dataObjInfo->objPath,
            _l1desc.dataObjInfo->rescHier,
            _l1desc.dataObjInfo->filePath);

        // If the size of the replica has changed since opening it, then update the size.
        if (_l1desc.dataObjInfo->dataSize != size_on_disk) {
            replica.size(size_on_disk);
            replica.mtime(SET_TIME_TO_NOW_KW);
        }
        // If the contents of the replica has changed, then update the last modified timestamp.
        else if (_l1desc.bytesWritten > 0) {
            replica.mtime(SET_TIME_TO_NOW_KW);
        }

        replica_state_table::instance().set_data_object_state(_l1desc.dataObjInfo->objPath, after, replica_state_table::state_type::after);
    } // update_replica_size

    auto update_replica_status(RsComm& _comm, const l1desc_t& _l1desc, const int _new_status) -> void
    {
        auto [after, after_lm] = get_data_object_state(_l1desc, replica_state_table::state_type::after);
        auto replica = *data_object::find_replica(after, _l1desc.dataObjInfo->rescHier);

        replica.replica_status(_new_status);

        replica_state_table::instance().set_data_object_state(_l1desc.dataObjInfo->objPath, after, replica_state_table::state_type::after);
    } // update_replica_status

    auto update_replica_checksum(RsComm& _comm, const l1desc_t& _l1desc) -> void
    {
        const auto& info = *_l1desc.dataObjInfo;
        constexpr const auto calculation = replica::verification_calculation::always;
        const auto checksum = replica::replica_checksum(_comm, info.objPath, info.rescName, calculation);

        auto [after, after_lm] = get_data_object_state(_l1desc, replica_state_table::state_type::after);
        auto replica = *data_object::find_replica(after, info.rescHier);

        replica.checksum(checksum);

        replica_state_table::instance().set_data_object_state(info.objPath, after, replica_state_table::state_type::after);
    } // update_replica_checksum

    auto free_l1_descriptor(int _l1desc_index) -> int
    {
        if (const auto ec = freeL1desc(_l1desc_index); ec != 0) {
            log::api::error("Failed to release L1 descriptor [error_code={}].", ec);
            return ec;
        }

        return 0;
    }

    auto get_data_object_state(const l1desc_t& _l1desc, const replica_state_table::state_type& _state) -> replica_state_table::data_object_handle
    {
        auto& rst = replica_state_table::instance();
        auto current_obj_tuple = rst.get_data_object_state(_l1desc.dataObjInfo->objPath, _state);
        if (!current_obj_tuple) {
            THROW(SYS_INTERNAL_ERR, fmt::format(
                "[{}] - no entry for [{}] in replica state table",
                __FUNCTION__, _l1desc.dataObjInfo->objPath));
        }
        return std::move(*current_obj_tuple);
    } // get_data_object_state

    auto update_catalog(RsComm& _comm, std::string_view _logical_path) -> void
    {
        char* output{};
        const auto input = irods::experimental::replica_state_table::to_json(_logical_path.data()).dump();

        if (const int ec = rs_data_object_finalize(&_comm, input.c_str(), &output); ec < 0) {
            THROW(ec, fmt::format(
                "[{}:{}] - finalize failed with [{}] and [{}]",
                __FUNCTION__, __LINE__, ec, output));
        }
    } // update_catalog

    auto rs_replica_close(RsComm* _comm, bytesBuf_t* _input) -> int
    {
        if (const auto [valid, msg] = is_input_valid(_input); !valid) {
            log::api::error(msg);
            return SYS_INVALID_INPUT_PARAM;
        }

        int ec = 0;
        json json_input;
        std::tie(ec, json_input) = parse_json(*_input);

        if (ec != 0) {
            log::api::error("Failed to parse JSON string [error_code={}]", ec);
            return ec;
        }

        int l1desc_index = -1;
        std::tie(ec, l1desc_index) = get_file_descriptor_index(json_input);

        if (ec != 0) {
            log::api::error("Failed to extract the L1 descriptor index from the JSON object [error_code={}]", ec);
            return ec;
        }

        if (l1desc_index < 3 || l1desc_index >= NUM_L1_DESC) {
            log::api::error("L1 descriptor index is out of range [error_code={}, fd={}].", BAD_INPUT_DESC_INDEX, l1desc_index);
            return BAD_INPUT_DESC_INDEX;
        }

        const auto& l1desc = L1desc[l1desc_index];
        //const auto send_notifications = !json_input.contains("send_notifications") || json_input.at("send_notifications").get<bool>();

        try {
            if (l1desc.inuseFlag != FD_INUSE) {
                log::api::error("File descriptor is not open [error_code={}, fd={}].", BAD_INPUT_DESC_INDEX, l1desc_index);
                return BAD_INPUT_DESC_INDEX;
            }

            // Redirect to the federated zone if the local L1 descriptor references a remote zone.
            if (l1desc.oprType == REMOTE_ZONE_OPR && l1desc.remoteZoneHost) {
                auto* conn = l1desc.remoteZoneHost->conn;

                auto j_in = json_input;
                j_in["fd"] = l1desc.remoteL1descInx;

                if (const auto ec = rc_replica_close(conn, j_in.dump().data()); ec != 0) {
                    log::api::error("Failed to close remote replica [error_code={}, remote_l1_descriptor={}",
                                    ec, l1desc.remoteL1descInx);
                    return ec;
                }

                return free_l1_descriptor(l1desc_index);
            }

            const auto is_write_operation = (O_RDONLY != (l1desc.dataObjInp->openFlags & O_ACCMODE));
            {
                const irods::at_scope_exit cleanup{[&l1desc]
                {
                    try {
                        auto& rst = replica_state_table::instance();
                        rst.erase_entry(l1desc.dataObjInfo->objPath);
                    }
                    catch (const irods::exception& e) {
                        irods::log(LOG_ERROR, fmt::format(
                            "[{}] - failed to erase replica_state_table entry:[{}:{}]",
                            __FUNCTION__, e.code(), e.what()));
                    }
                    catch (const std::exception& e) {
                        irods::log(LOG_ERROR, fmt::format(
                            "[{}] - failed to erase replica_state_table entry:[{}]",
                            __FUNCTION__, e.what()));
                    }
                    catch (...) {
                        irods::log(LOG_ERROR, fmt::format(
                            "[{}] - unknown error occurred while erasing replica_state_table entry",
                            __FUNCTION__));
                    }
                }};

                try {
                    // Allow updates to the replica's catalog information if the stream supports
                    // write operations (i.e. the stream is opened in write-only or read-write mode).
                    const auto update_status = !json_input.contains("update_status") || json_input.at("update_status").get<bool>();
                    if (is_write_operation) {
                        const auto update_size = !json_input.contains("update_size") || json_input.at("update_size").get<bool>();

                        // Update the replica's information in the catalog if requested.
                        if (update_size && update_status) {
                            update_replica_size_and_status(*_comm, l1desc);
                        }
                        else if (update_size) {
                            update_replica_size(*_comm, l1desc);
                        }
                        else if (update_status) {
                            update_replica_status(*_comm, l1desc, GOOD_REPLICA);
                        }

                        // [Re]compute a checksum for the replica if requested.
                        if (json_input.contains("compute_checksum") && json_input.at("compute_checksum").get<bool>()) {
                            update_replica_checksum(*_comm, l1desc);
                        }
                    }
                    else {
                        if (update_status) {
                            update_replica_status(*_comm, l1desc, GOOD_REPLICA);
                        }
                    }

                    update_catalog(*_comm, l1desc.dataObjInfo->objPath);
                }
                catch (const irods::exception& e) {
                    irods::log(LOG_ERROR, fmt::format("[{}] - failed to update replica:[{}]", __FUNCTION__, e.what()));
                    update_replica_status(*_comm, l1desc, STALE_REPLICA);
                    update_catalog(*_comm, l1desc.dataObjInfo->objPath);
                    return e.code();
                }
            }

            // Remove the agent's PID from the replica access table.
            auto entry = is_write_operation
                ? ix::replica_access_table::instance().erase_pid(l1desc.replica_token, getpid())
                : std::nullopt;

            // Close the underlying file object.
            if (const auto ec = close_physical_object(*_comm, l1desc.l3descInx); ec != 0) {
                if (entry) {
                    ix::replica_access_table::instance().restore(*entry);
                }

                log::api::error("Failed to close file object [error_code={}].", ec);
                update_replica_status(*_comm, l1desc, STALE_REPLICA);
                return ec;
            }

            const auto ec = free_l1_descriptor(l1desc_index);

            if (ec != 0) {
                // TODO: need to make sure the index is still valid before using
                update_replica_status(*_comm, l1desc, STALE_REPLICA);
            }

            return ec;
        }
        catch (const json::type_error& e) {
            log::api::error("Failed to extract property from JSON object [error_code={}]", SYS_INTERNAL_ERR);
            update_replica_status(*_comm, l1desc, STALE_REPLICA);
            return SYS_INTERNAL_ERR;
        }
        catch (const irods::exception& e) {
            log::api::error("{} [error_code={}]", e.what(), e.code());
            update_replica_status(*_comm, l1desc, STALE_REPLICA);
            return e.code();
        }
        catch (const fs::filesystem_error& e) {
            log::api::error("{} [error_code={}]", e.what(), e.code().value());
            update_replica_status(*_comm, l1desc, STALE_REPLICA);
            return e.code().value();
        }
        catch (const std::exception& e) {
            log::api::error("An unexpected error occurred while closing the replica. {} [error_code={}]",
                            e.what(), SYS_INTERNAL_ERR);
            update_replica_status(*_comm, l1desc, STALE_REPLICA);
            return SYS_INTERNAL_ERR;
        }
    }

    const operation op = rs_replica_close;
    #define CALL_REPLICA_CLOSE call_replica_close
} // anonymous namespace

#else // RODS_SERVER

//
// Client-side Implementation
//

namespace
{
    using operation = std::function<int(rcComm_t*, bytesBuf_t*)>;
    const operation op{};
    #define CALL_REPLICA_CLOSE nullptr
} // anonymous namespace

#endif // RODS_SERVER

// The plugin factory function must always be defined.
extern "C"
auto plugin_factory(const std::string& _instance_name,
                    const std::string& _context) -> irods::api_entry*
{
#ifdef RODS_SERVER
    irods::client_api_whitelist::instance().add(REPLICA_CLOSE_APN);
#endif // RODS_SERVER

    // clang-format off
    irods::apidef_t def{REPLICA_CLOSE_APN,                // API number
                        RODS_API_VERSION,                 // API version
                        NO_USER_AUTH,                     // Client auth
                        NO_USER_AUTH,                     // Proxy auth
                        "BytesBuf_PI", 0,                 // In PI / bs flag
                        nullptr, 0,                       // Out PI / bs flag
                        op,                               // Operation
                        "api_replica_close",              // Operation name
                        nullptr,                          // Clear function
                        (funcPtr) CALL_REPLICA_CLOSE};
    // clang-format on

    auto* api = new irods::api_entry{def};

    api->in_pack_key = "BytesBuf_PI";
    api->in_pack_value = BytesBuf_PI;

    return api;
}

