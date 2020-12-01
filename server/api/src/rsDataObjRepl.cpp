#include "apiNumber.h"
#include "dataObjClose.h"
#include "dataObjCreate.h"
#include "dataObjGet.h"
#include "dataObjLock.h"
#include "dataObjOpen.h"
#include "dataObjOpr.hpp"
#include "dataObjPut.h"
#include "dataObjRepl.h"
#include "dataObjTrim.h"
#include "fileStageToCache.h"
#include "fileSyncToArch.h"
#include "getRemoteZoneResc.h"
#include "getRescQuota.h"
#include "icatDefines.h"
#include "l3FileGetSingleBuf.h"
#include "l3FilePutSingleBuf.h"
#include "miscServerFunct.hpp"
#include "objMetaOpr.hpp"
#include "physPath.hpp"
#include "resource.hpp"
#include "rodsLog.h"
#include "rsDataCopy.hpp"
#include "rsDataObjClose.hpp"
#include "rsDataObjCreate.hpp"
#include "rsDataObjGet.hpp"
#include "rsDataObjOpen.hpp"
#include "rsDataObjPut.hpp"
#include "rsDataObjRead.hpp"
#include "rsDataObjRepl.hpp"
#include "rsDataObjUnlink.hpp"
#include "rsDataObjWrite.hpp"
#include "rsFileStageToCache.hpp"
#include "rsFileSyncToArch.hpp"
#include "rsGetRescQuota.hpp"
#include "rsL3FileGetSingleBuf.hpp"
#include "rsL3FilePutSingleBuf.hpp"
#include "rsUnbunAndRegPhyBunfile.hpp"
#include "rsUnregDataObj.hpp"
#include "rs_replica_close.hpp"
#include "specColl.hpp"
#include "unbunAndRegPhyBunfile.h"

#include "finalize_utilities.hpp"
#include "irods_at_scope_exit.hpp"
#include "irods_log.hpp"
#include "irods_logger.hpp"
#include "irods_random.hpp"
#include "irods_resource_backport.hpp"
#include "irods_resource_redirect.hpp"
#include "irods_server_api_call.hpp"
#include "irods_server_properties.hpp"
#include "irods_stacktrace.hpp"
#include "irods_string_tokenize.hpp"
#include "key_value_proxy.hpp"
#include "key_value_proxy.hpp"
#include "replica_access_table.hpp"
#include "voting.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"
#include "replica_proxy.hpp"

#include <string_view>
#include <vector>

#include "fmt/format.h"

namespace
{
    auto finalize_source_replica(RsComm& _comm, l1desc& _l1desc, DataObjInfo& _info) -> int
    {
        if (_l1desc.purgeCacheFlag) {
            irods::purge_cache(_comm, _info);
        }

        irods::apply_metadata_from_cond_input(_comm, *_l1desc.dataObjInp);
        irods::apply_acl_from_cond_input(_comm, *_l1desc.dataObjInp);

        // TODO: set replica state...?

        return 0;
    } // finalize_replica_with_no_bytes_written

    auto perform_checksum_operation_for_finalize(
        RsComm& _comm,
        l1desc& _l1desc,
        DataObjInfo& _source_info,
        DataObjInfo& _destination_info) -> std::string
    {
        char* checksum_string = nullptr;
        irods::at_scope_exit free_checksum_string{[&checksum_string] { free(checksum_string); }};

        auto destination_replica = irods::experimental::replica::make_replica_proxy(_destination_info);
        auto source_replica = irods::experimental::replica::make_replica_proxy(_source_info);

        if (source_replica.checksum().length() > 0 && STALE_REPLICA != source_replica.replica_status()) {
            destination_replica.cond_input()[ORIG_CHKSUM_KW] = source_replica.checksum();

            irods::log(LOG_DEBUG, fmt::format(
                "[{}:{}] - verifying checksum for [{}],source:[{}]",
                __FUNCTION__, __LINE__, destination_replica.logical_path(), source_replica.checksum()));

            if (const int ec = _dataObjChksum(&_comm, destination_replica.get(), &checksum_string); ec < 0) {
                destination_replica.checksum("");

                if (DIRECT_ARCHIVE_ACCESS == ec) {
                    destination_replica.checksum(source_replica.checksum());
                    return source_replica.checksum().data();
                }

                THROW(ec, fmt::format(
                    "{}: _dataObjChksum error for {}, status = {}",
                    __FUNCTION__, destination_replica.logical_path(), ec));
            }

            if (!checksum_string) {
                THROW(SYS_INTERNAL_NULL_INPUT_ERR, "checksum_string is NULL");
            }

            destination_replica.checksum(checksum_string);

            if (source_replica.checksum() != checksum_string) {
                THROW(USER_CHKSUM_MISMATCH, fmt::format(
                    "{}: chksum mismatch for {} src [{}] new [{}]",
                    __FUNCTION__, destination_replica.logical_path(), source_replica.checksum(), checksum_string));
            }

            return destination_replica.checksum().data();
        }

        if (!_l1desc.chksumFlag) {
            if (destination_replica.checksum().empty()) {
                return {};
            }
            _l1desc.chksumFlag = VERIFY_CHKSUM;
        }

        if (VERIFY_CHKSUM == _l1desc.chksumFlag) {
            if (!std::string_view{_l1desc.chksum}.empty()) {
                return irods::verify_checksum(_comm, *destination_replica.get(), _l1desc.chksum);
            }

            if (!destination_replica.checksum().empty()) {
                destination_replica.cond_input()[ORIG_CHKSUM_KW] = destination_replica.checksum();
            }

            if (const int ec = _dataObjChksum(&_comm, destination_replica.get(), &checksum_string); ec < 0) {
                THROW(ec, "failed in _dataObjChksum");
            }

            if (!checksum_string) {
                THROW(SYS_INTERNAL_NULL_INPUT_ERR, "checksum_string is NULL");
            }

            if (!destination_replica.checksum().empty()) {
                destination_replica.cond_input().erase(ORIG_CHKSUM_KW);

                /* for replication, the chksum in dataObjInfo was duplicated */
                if (destination_replica.checksum() != checksum_string) {
                    THROW(USER_CHKSUM_MISMATCH, fmt::format(
                        "{}:mismach chksum for {}.Rcat={},comp {}",
                        __FUNCTION__, destination_replica.logical_path(), destination_replica.checksum(), checksum_string));
                }
            }

            return {checksum_string};
        }

        return irods::register_new_checksum(_comm, *destination_replica.get(), _l1desc.chksum);
    } // perform_checksum_operation_for_finalize

    auto update_checksum_if_needed(RsComm& _comm, l1desc& _l1desc, DataObjInfo& _source_info, DataObjInfo& _destination_info) -> std::string
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_l1desc.dataObjInp->condInput);
        bool update_checksum = !cond_input.contains(NO_CHK_COPY_LEN_KW);
        if (!std::string_view{_destination_info.chksum}.empty()) {
            _l1desc.chksumFlag = REG_CHKSUM;
            update_checksum = true;
        }

        if (!update_checksum) {
            return "";
        }

        try {
            return perform_checksum_operation_for_finalize(_comm, _l1desc, _destination_info, _source_info);
        }
        catch (const irods::exception& e) {
            _destination_info.replStatus = STALE_REPLICA;

            keyValPair_t regParam{};
            auto kvp = irods::experimental::make_key_value_proxy(regParam);
            kvp[IN_PDMO_KW] = _destination_info.rescHier;
            kvp[REPL_STATUS_KW] = std::to_string(_destination_info.replStatus);
            if (cond_input.contains(ADMIN_KW)) {
                kvp[ADMIN_KW] = "";
            }

            modDataObjMeta_t inp{};
            inp.dataObjInfo = &_destination_info;
            inp.regParam = kvp.get();

            if (const int ec = rsModDataObjMeta(&_comm, &inp); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "{} - rsModDataObjMeta failed [{}]",
                    __FUNCTION__, ec));
            }

            throw;
        }
    } // update_checksum_if_needed

    auto finalize_destination_replica(RsComm& _comm, l1desc& _l1desc, DataObjInfo& _source_info, DataObjInfo& _destination_info) -> int
    {
        auto source_replica = irods::experimental::replica::make_replica_proxy(_source_info);
        auto destination_replica = irods::experimental::replica::make_replica_proxy(_destination_info);

        try {
            const bool verify_size = !getValByKey(&_l1desc.dataObjInp->condInput, NO_CHK_COPY_LEN_KW);
            const auto size_in_vault = irods::get_size_in_vault(_comm, _destination_info, verify_size, _l1desc.dataSize);
            destination_replica.size(size_in_vault);
        }
        catch (const irods::exception& e) {
            destination_replica.replica_status(STALE_REPLICA);

            keyValPair_t regParam{};
            auto kvp = irods::experimental::make_key_value_proxy(regParam);

            kvp[IN_PDMO_KW] = destination_replica.hierarchy();
            kvp[REPL_STATUS_KW] = std::to_string(destination_replica.replica_status());

            if (getValByKey(&_l1desc.dataObjInp->condInput, ADMIN_KW)) {
                kvp[ADMIN_KW] = "";
            }

            modDataObjMeta_t inp{};
            inp.dataObjInfo = &_destination_info;
            inp.regParam = kvp.get();

            if (const int ec = rsModDataObjMeta(&_comm, &inp); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "{} - rsModDataObjMeta failed [{}]",
                    __FUNCTION__, ec));
            }

            throw;
        }

        const auto checksum = update_checksum_if_needed(_comm, _l1desc, _source_info, _destination_info);
        if (!checksum.empty()) {
            irods::experimental::key_value_proxy{_l1desc.dataObjInp->condInput}[CHKSUM_KW] = checksum;
        }

        auto [reg_param, lm] = irods::experimental::make_key_value_proxy({{OPEN_TYPE_KW, std::to_string(_l1desc.openType)}});
        reg_param[REPL_STATUS_KW] = std::to_string(source_replica.replica_status());
        reg_param[DATA_SIZE_KW] = std::to_string(source_replica.size());
        reg_param[DATA_MODIFY_KW] = std::to_string((int)time(nullptr));
        reg_param[FILE_PATH_KW] = destination_replica.physical_path();
        destination_replica.size(source_replica.size());

        const auto cond_input = irods::experimental::make_key_value_proxy(_l1desc.dataObjInp->condInput);
        if (cond_input.contains(ADMIN_KW)) {
            reg_param[ADMIN_KW] = cond_input.at(ADMIN_KW);
        }
        if (const char* pdmo_kw = getValByKey(&_l1desc.dataObjInp->condInput, IN_PDMO_KW); pdmo_kw) {
            reg_param[IN_PDMO_KW] = pdmo_kw;
        }
        if (cond_input.contains(SYNC_OBJ_KW)) {
            reg_param[SYNC_OBJ_KW] = cond_input.at(SYNC_OBJ_KW);
        }
        if (cond_input.contains(CHKSUM_KW)) {
            reg_param[CHKSUM_KW] = cond_input.at(CHKSUM_KW);
        }

        modDataObjMeta_t mod_inp{};
        mod_inp.dataObjInfo = destination_replica.get();
        mod_inp.regParam = reg_param.get();
        const int status = rsModDataObjMeta(&_comm, &mod_inp);

        if (CREATE_TYPE == _l1desc.openType) {
            updatequotaOverrun(destination_replica.hierarchy().data(), destination_replica.size(), ALL_QUOTA);
        }

        if (status < 0) {
            _l1desc.oprStatus = status;

            if (CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME != status) {
                l3Unlink(&_comm, destination_replica.get());
            }

            irods::log(LOG_NOTICE, fmt::format(
                    "{}: RegReplica/ModDataObjMeta {} err. stat = {}",
                    __FUNCTION__, destination_replica.logical_path(), status));
        }

        //l1desc.bytesWritten = l1desc.dataObjInfo->dataSize;
        //opened_replica.size(l1desc.dataObjInfo->dataSize); // no-op?

        //if (L1desc[_fd].purgeCacheFlag) {
            //irods::purge_cache(_comm, *l1desc.dataObjInfo);
        //}

        return status;
    } // finalize_destination_replica

    int close_replica(RsComm& _comm, const int _fd)
    {
        nlohmann::json in_json;
        in_json["fd"] = _fd;
        in_json["send_notifications"] = false;
        const auto input = in_json.dump();

        if (const int ec = rs_replica_close(&_comm, input.data()); ec < 0) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}] - error closing replica; ec:[{}]",
                __FUNCTION__, ec));

            return ec;
        }

        return 0;
    } // close_replica

    DataObjInp init_source_replica_input(RsComm& _comm, const DataObjInp& _inp)
    {
        DataObjInp source_data_obj_inp = _inp;
        replKeyVal(&_inp.condInput, &source_data_obj_inp.condInput);
        auto cond_input = irods::experimental::make_key_value_proxy(source_data_obj_inp.condInput);

        // Remove existing keywords used for destination resource
        cond_input.erase(DEST_RESC_NAME_KW);
        cond_input.erase(DEST_RESC_HIER_STR_KW);

        return source_data_obj_inp;
    } // init_source_replica_input

    irods::file_object_ptr get_source_replica_info(RsComm& _comm, DataObjInp& _inp)
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

        if (cond_input.contains(RESC_HIER_STR_KW)) {
            irods::file_object_ptr obj{new irods::file_object()};
            irods::error err = irods::file_object_factory(&_comm, &_inp, obj);
            if (!err.ok()) {
                THROW(err.code(), err.result());
            }
            return obj;
        }

        auto [obj, hier] = irods::resolve_resource_hierarchy(irods::OPEN_OPERATION, &_comm, _inp);

        cond_input[RESC_HIER_STR_KW] = hier;

        return obj;
    } // get_source_replica_info

    DataObjInp init_destination_replica_input(RsComm& _comm, const DataObjInp& _inp)
    {
        DataObjInp destination_data_obj_inp = _inp;
        replKeyVal(&_inp.condInput, &destination_data_obj_inp.condInput);
        auto cond_input = irods::experimental::make_key_value_proxy(destination_data_obj_inp.condInput);

        // Remove existing keywords used for source resource
        cond_input.erase(RESC_NAME_KW);
        cond_input.erase(RESC_HIER_STR_KW);

        return destination_data_obj_inp;
    } // init_destination_replica_input

    irods::file_object_ptr get_destination_replica_info(RsComm& _comm, DataObjInp& _inp)
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

        if (cond_input.contains(DEST_RESC_HIER_STR_KW)) {
            cond_input[RESC_HIER_STR_KW] = cond_input.at(DEST_RESC_HIER_STR_KW).value();
            irods::file_object_ptr obj{new irods::file_object()};
            irods::error err = irods::file_object_factory(&_comm, &_inp, obj);
            if (!err.ok()) {
                THROW(err.code(), err.result());
            }
            return obj;
        }

        std::string replica_number;
        if (cond_input.contains(REPL_NUM_KW)) {
            replica_number = cond_input[REPL_NUM_KW].value();

            // This keyword must be removed temporarily so that the voting mechanism does
            // not misinterpret it and change the operation from a CREATE to a WRITE.
            // See server/core/src/irods_resource_redirect.cpp for details.
            cond_input.erase(REPL_NUM_KW);
        }

        irods::at_scope_exit restore_replica_number_keyword{[&replica_number, &cond_input] {
            if (!replica_number.empty()) {
                cond_input[REPL_NUM_KW] = replica_number;
            }
        }};

        // Get the destination resource that the client specified, or use the default resource
        if (!cond_input.contains(DEST_RESC_HIER_STR_KW) &&
            !cond_input.contains(DEST_RESC_NAME_KW) &&
            cond_input.contains(DEF_RESC_NAME_KW)) {
            cond_input[DEST_RESC_NAME_KW] = cond_input.at(DEF_RESC_NAME_KW).value();
        }

        auto [obj, hier] = irods::resolve_resource_hierarchy(
            irods::CREATE_OPERATION, &_comm, _inp);

        cond_input[RESC_HIER_STR_KW] = hier;
        cond_input[DEST_RESC_HIER_STR_KW] = hier;

        return obj;
    } // get_destination_replica_info

    int open_source_replica(RsComm& _comm, DataObjInp& _inp)
    {
        _inp.oprType = REPLICATE_SRC;
        _inp.openFlags = O_RDONLY;
        int source_l1descInx = rsDataObjOpen(&_comm, &_inp);
        if (source_l1descInx < 0) {
            return source_l1descInx;
        }

        const auto* info = L1desc[source_l1descInx].dataObjInfo;

        irods::log(LOG_DEBUG, fmt::format(
            "[{}:{}] - opened source replica [{}] on [{}] (repl [{}])",
            __FUNCTION__, __LINE__, info->objPath, info->rescHier, info->replNum));

        // TODO: Consider using force flag and making this part of the voting process
        if (GOOD_REPLICA != L1desc[source_l1descInx].dataObjInfo->replStatus) {
            close_replica(_comm, source_l1descInx);
            // TODO: need to stale-ify?
            return SYS_NO_GOOD_REPLICA;
        }

        return source_l1descInx;
    } // open_source_replica

    int open_destination_replica(RsComm& _comm, DataObjInp& _inp, const int _fd)
    {
        auto kvp = irods::experimental::make_key_value_proxy(_inp.condInput);
        kvp[REG_REPL_KW] = "";
        kvp[DATA_ID_KW] = std::to_string(L1desc[_fd].dataObjInfo->dataId);
        kvp[SOURCE_L1_DESC_KW] = std::to_string(_fd);
        kvp.erase(PURGE_CACHE_KW);

        _inp.oprType = REPLICATE_DEST;
        _inp.openFlags = O_CREAT | O_WRONLY | O_TRUNC;

        irods::log(LOG_DEBUG, fmt::format(
            "[{}:{}] - opening destination replica for [{}] (id:[{}]) on [{}]",
            __FUNCTION__,
            __LINE__,
            _inp.objPath,
            kvp.at(DATA_ID_KW).value(),
            kvp.at(RESC_HIER_STR_KW).value()));

        return rsDataObjOpen(&_comm, &_inp);
    } // open_destination_replica

    int replicate_data(RsComm& _comm, DataObjInp& _source_inp, DataObjInp& _destination_inp)
    {
        // Open source replica
        int source_l1descInx = open_source_replica(_comm, _source_inp);
        if (source_l1descInx < 0) {
            THROW(source_l1descInx, "Failed opening source replica");
        }

        // Open destination replica
        int destination_l1descInx = open_destination_replica(_comm, _destination_inp, source_l1descInx);
        if (destination_l1descInx < 0) {
            close_replica(_comm, source_l1descInx);
            // TODO: mark as stale?
            THROW(destination_l1descInx, "Failed opening destination replica");
        }
        L1desc[destination_l1descInx].srcL1descInx = source_l1descInx;
        L1desc[destination_l1descInx].dataSize = L1desc[source_l1descInx].dataObjInfo->dataSize;

        // Copy data from source to destination
        int status = dataObjCopy(&_comm, destination_l1descInx);
        if (status < 0) {
            rodsLog(LOG_ERROR, "[%s] - dataObjCopy failed for [%s]", __FUNCTION__, _destination_inp.objPath);
            L1desc[destination_l1descInx].bytesWritten = status;
        }
        else {
            L1desc[destination_l1descInx].bytesWritten = L1desc[destination_l1descInx].dataObjInfo->dataSize;
        }

        // Save the token for the replica access table so that it can be removed
        // in the event of a failure in close. On failure, the entry is restored,
        // but this will prevent retries of the operation as the token information
        // is lost by the time we have returned to the caller.
        const auto token = L1desc[destination_l1descInx].replica_token;

        auto source_fd = irods::duplicate_l1_descriptor(L1desc[source_l1descInx]);
        auto destination_fd = irods::duplicate_l1_descriptor(L1desc[destination_l1descInx]);
        irods::at_scope_exit free_fd{[&source_fd, &destination_fd]
            {
                freeL1desc_struct(source_fd);
                freeL1desc_struct(destination_fd);
            }
        };

        auto [source_replica, source_replica_lm] = irods::experimental::replica::duplicate_replica(*L1desc[source_l1descInx].dataObjInfo);
        auto [destination_replica, destination_replica_lm] = irods::experimental::replica::duplicate_replica(*L1desc[destination_l1descInx].dataObjInfo);

        // Close source replica
        if (const int ec = close_replica(_comm, source_l1descInx); ec < 0) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}] - closing source replica [{}] failed with [{}]",
                __FUNCTION__, _source_inp.objPath, ec));

            if (status >= 0) {
                status = ec;
            }
        }

        // Close destination replica
        if (const int ec = close_replica(_comm, destination_l1descInx); ec < 0) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}] - closing destination replica [{}] failed with [{}]",
                __FUNCTION__, _destination_inp.objPath, ec));

            if (status >= 0) {
                status = ec;
            }

            auto& rat = irods::experimental::replica_access_table::instance();
            rat.erase_pid(token, getpid());
        }

        // finalize source replica
        try {
            if (const int ec = finalize_source_replica(_comm, source_fd, *source_replica.get()); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "[{}] - closing source replica [{}] failed with [{}]",
                    __FUNCTION__, source_replica.logical_path(), ec));

                if (status >= 0) {
                    status = ec;
                }
            }
        }
        catch (const irods::exception& e) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}:{}] - error finalizing replica; [{}], ec:[{}]",
                __FUNCTION__, __LINE__, e.what(), e.code()));

            if (status >= 0) {
                status = e.code();
            }
        }

        // finalize destination replica
        try {
            if (const int ec = finalize_destination_replica(_comm, destination_fd, *source_replica.get(), *destination_replica.get()); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "[{}] - closing destination replica [{}] failed with [{}]",
                    __FUNCTION__, destination_replica.logical_path(), ec));

                if (status >= 0) {
                    status = ec;
                }
            }
        }
        catch (const irods::exception& e) {
            irods::log(LOG_ERROR, fmt::format(
                "[{}:{}] - error finalizing replica; [{}], ec:[{}]",
                __FUNCTION__, __LINE__, e.what(), e.code()));

            if (status >= 0) {
                status = e.code();
            }
        }

        return status;
    } // replicate_data

    int repl_data_obj(RsComm& _comm, const dataObjInp_t& _inp)
    {
        namespace irv = irods::experimental::resource::voting;

        // Make sure the requested source and destination resources are valid
        dataObjInp_t destination_inp{};
        dataObjInp_t source_inp{};
        const irods::at_scope_exit free_cond_inputs{[&destination_inp, &source_inp]() {
            clearKeyVal(&destination_inp.condInput);
            clearKeyVal(&source_inp.condInput);
        }};

        source_inp = init_source_replica_input(_comm, _inp);
        //auto source_cond_input = irods::experimental::make_key_value_proxy(source_inp.condInput);
        auto source_obj = get_source_replica_info(_comm, source_inp);

        destination_inp = init_destination_replica_input(_comm, _inp);
        //auto destination_cond_input = irods::experimental::make_key_value_proxy(destination_inp.condInput);
        auto destination_obj = get_destination_replica_info(_comm, destination_inp);

        int status{};
        if (getValByKey(&_inp.condInput, ALL_KW)) {
            for (const auto& r : destination_obj->replicas()) {
                irods::log(LOG_DEBUG, fmt::format(
                    "[{}:{}] - hier:[{}],status:[{}],vote:[{}]",
                    __FUNCTION__, __LINE__,
                    r.resc_hier(),
                    r.replica_status(),
                    r.vote()));
                if (GOOD_REPLICA == (r.replica_status() & 0x0F)) {
                    continue;
                }
                if (r.vote() > irv::vote::zero) {
                    addKeyVal(&destination_inp.condInput, RESC_HIER_STR_KW, r.resc_hier().c_str());
                    status = replicate_data(_comm, source_inp, destination_inp);
                }
            }
            return status;
        }

        const char* dest_hier = getValByKey(&destination_inp.condInput, RESC_HIER_STR_KW);
        for (const auto& r : destination_obj->replicas()) {
            // TODO: #4010 - This short-circuits resource logic for handling good replicas
            if (r.resc_hier() == dest_hier) {
                if (GOOD_REPLICA == r.replica_status()) {
                    const char* source_hier = getValByKey(&source_inp.condInput, RESC_HIER_STR_KW);
                    irods::log(LOG_DEBUG, fmt::format(
                        "[{}:{}] - hierarchy contains good replica already, source:[{}],dest:[{}]",
                        __FUNCTION__, __LINE__, dest_hier, source_hier));
                    return 0;
                }
                break;
            }
        }
        return replicate_data(_comm, source_inp, destination_inp);
    } // repl_data_obj

    int singleL1Copy(rsComm_t *rsComm, dataCopyInp_t& dataCopyInp)
    {
        int trans_buff_size;
        try {
            trans_buff_size = irods::get_advanced_setting<const int>(irods::CFG_TRANS_BUFFER_SIZE_FOR_PARA_TRANS) * 1024 * 1024;
        } catch ( const irods::exception& e ) {
            irods::log(e);
            return e.code();
        }

        dataOprInp_t* dataOprInp = &dataCopyInp.dataOprInp;
        int destL1descInx = dataCopyInp.portalOprOut.l1descInx;
        int srcL1descInx = L1desc[destL1descInx].srcL1descInx;

        openedDataObjInp_t dataObjReadInp{};
        dataObjReadInp.l1descInx = srcL1descInx;
        dataObjReadInp.len = trans_buff_size;

        bytesBuf_t dataObjReadInpBBuf{};
        dataObjReadInpBBuf.buf = malloc(dataObjReadInp.len);
        dataObjReadInpBBuf.len = dataObjReadInp.len;
        const irods::at_scope_exit free_data_obj_read_inp_bbuf{[&dataObjReadInpBBuf]() {
            free(dataObjReadInpBBuf.buf);
        }};

        openedDataObjInp_t dataObjWriteInp{};
        dataObjWriteInp.l1descInx = destL1descInx;

        bytesBuf_t dataObjWriteInpBBuf{};
        dataObjWriteInpBBuf.buf = dataObjReadInpBBuf.buf;
        dataObjWriteInpBBuf.len = 0;

        int bytesRead{};
        rodsLong_t totalWritten = 0;
        while ((bytesRead = rsDataObjRead(rsComm, &dataObjReadInp, &dataObjReadInpBBuf)) > 0) {
            dataObjWriteInp.len = bytesRead;
            dataObjWriteInpBBuf.len = bytesRead;
            int bytesWritten = rsDataObjWrite(rsComm, &dataObjWriteInp, &dataObjWriteInpBBuf);
            if (bytesWritten != bytesRead) {
                rodsLog(LOG_ERROR,
                        "%s: Read %d bytes, Wrote %d bytes.\n ",
                        __FUNCTION__, bytesRead, bytesWritten );
                return SYS_COPY_LEN_ERR;
            }
            totalWritten += bytesWritten;
        }

        if (dataOprInp->dataSize > 0 &&
            !getValByKey(&dataOprInp->condInput, NO_CHK_COPY_LEN_KW) &&
            totalWritten != dataOprInp->dataSize) {
            rodsLog(LOG_ERROR,
                    "%s: totalWritten %lld dataSize %lld mismatch",
                    __FUNCTION__, totalWritten, dataOprInp->dataSize);
            return SYS_COPY_LEN_ERR;
        }
        return 0;
    } // singleL1Copy
} // anonymous namespace

int rsDataObjRepl(
    rsComm_t *rsComm,
    dataObjInp_t *dataObjInp,
    transferStat_t **transStat) {
    if (!dataObjInp) {
        return SYS_INTERNAL_NULL_INPUT_ERR;
    }

    // -S and -n are not compatible
    if (getValByKey(&dataObjInp->condInput, RESC_NAME_KW) &&
        getValByKey(&dataObjInp->condInput, REPL_NUM_KW)) {
        return USER_INCOMPATIBLE_PARAMS;
    }

    // -S and -r are not compatible
    if (getValByKey(&dataObjInp->condInput, RESC_NAME_KW) &&
        getValByKey(&dataObjInp->condInput, RECURSIVE_OPR__KW)) {
        return USER_INCOMPATIBLE_PARAMS;
    }

    // -a and -R are not compatible
    if (getValByKey(&dataObjInp->condInput, ALL_KW) &&
        getValByKey(&dataObjInp->condInput, DEST_RESC_NAME_KW)) {
        return USER_INCOMPATIBLE_PARAMS;
    }

    // Must be a privileged user to invoke SU
    if (getValByKey(&dataObjInp->condInput, SU_CLIENT_USER_KW) &&
        rsComm->proxyUser.authInfo.authFlag < REMOTE_PRIV_USER_AUTH) {
        return CAT_INSUFFICIENT_PRIVILEGE_LEVEL;
    }

    // Resolve path in linked collection if applicable
    dataObjInfo_t *dataObjInfo{};
    const irods::at_scope_exit free_data_obj_info{[dataObjInfo]() {
        freeAllDataObjInfo(dataObjInfo);
    }};
    int status = resolvePathInSpecColl( rsComm, dataObjInp->objPath,
                                    READ_COLL_PERM, 0, &dataObjInfo );
    if (status == DATA_OBJ_T && dataObjInfo && dataObjInfo->specColl) {
        if (dataObjInfo->specColl->collClass != LINKED_COLL) {
            return SYS_REG_OBJ_IN_SPEC_COLL;
        }
        rstrcpy(dataObjInp->objPath, dataObjInfo->objPath, MAX_NAME_LEN);
    }

    rodsServerHost_t *rodsServerHost{};
    const int remoteFlag = getAndConnRemoteZone(rsComm, dataObjInp, &rodsServerHost, REMOTE_OPEN);
    if ( remoteFlag < 0 ) {
        return remoteFlag;
    }
    else if (remoteFlag == REMOTE_HOST) {
        *transStat = (transferStat_t*)malloc(sizeof(transferStat_t));
        memset(*transStat, 0, sizeof(transferStat_t));
        status = _rcDataObjRepl(rodsServerHost->conn, dataObjInp, transStat);
        return status;
    }

    try {
        addKeyVal(&dataObjInp->condInput, IN_REPL_KW, "");
        status = repl_data_obj(*rsComm, *dataObjInp);
        rmKeyVal(&dataObjInp->condInput, IN_REPL_KW);
    }
    catch (const irods::exception& e) {
        irods::log(e);
        status = e.code();
    }
    catch (const std::exception& e) {
        irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.what()));
        status = SYS_LIBRARY_ERROR;
    }
    catch (...) {
        irods::log(LOG_ERROR, fmt::format("[{}:{}] - unknown error occurred", __FUNCTION__, __LINE__));
        status = SYS_UNKNOWN_ERROR;
    }

    if (status < 0 && status != DIRECT_ARCHIVE_ACCESS) {
        rodsLog(LOG_NOTICE, "%s - Failed to replicate data object. status:[%d]",
                __FUNCTION__, status);
    }
    return (status == DIRECT_ARCHIVE_ACCESS) ? 0 : status;
} // rsDataObjRepl

int dataObjCopy(rsComm_t* rsComm, int _destination_l1descInx)
{
    int source_l1descInx = L1desc[_destination_l1descInx].srcL1descInx;
    if (source_l1descInx < 3) {
        irods::log(LOG_ERROR, fmt::format(
            "[{}] - source l1 descriptor out of range:[{}]",
            __FUNCTION__, source_l1descInx));
        return SYS_FILE_DESC_OUT_OF_RANGE;
    }

    int srcRemoteFlag{};
    int srcL3descInx = L1desc[source_l1descInx].l3descInx;
    if (L1desc[source_l1descInx].remoteZoneHost) {
        srcRemoteFlag = REMOTE_ZONE_HOST;
    }
    else {
        srcRemoteFlag = FileDesc[srcL3descInx].rodsServerHost->localFlag;
    }
    int destRemoteFlag{};
    int destL3descInx = L1desc[_destination_l1descInx].l3descInx;
    if (L1desc[_destination_l1descInx].remoteZoneHost) {
        destRemoteFlag = REMOTE_ZONE_HOST;
    }
    else {
        destRemoteFlag = FileDesc[destL3descInx].rodsServerHost->localFlag;
    }

    dataCopyInp_t dataCopyInp{};
    const irods::at_scope_exit clear_cond_input{[&dataCopyInp]() {
        clearKeyVal(&dataCopyInp.dataOprInp.condInput);
    }};

    portalOprOut_t* portalOprOut{};
    if (srcRemoteFlag == REMOTE_ZONE_HOST &&
        destRemoteFlag == REMOTE_ZONE_HOST) {
        // Destination: remote zone
        // Source: remote zone
        initDataOprInp(&dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_REM_OPR);
        L1desc[_destination_l1descInx].dataObjInp->numThreads = 0;
        dataCopyInp.portalOprOut.l1descInx = _destination_l1descInx;
        return singleL1Copy(rsComm, dataCopyInp);
    }

    if (srcRemoteFlag != REMOTE_ZONE_HOST &&
        destRemoteFlag != REMOTE_ZONE_HOST &&
        FileDesc[srcL3descInx].rodsServerHost == FileDesc[destL3descInx].rodsServerHost) {
        // Destination: local zone
        // Source: local zone
        // Source and destination host are the same
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, SAME_HOST_COPY_OPR );
        dataCopyInp.portalOprOut.numThreads = dataCopyInp.dataOprInp.numThreads;
        if ( srcRemoteFlag == LOCAL_HOST ) {
            addKeyVal(&dataCopyInp.dataOprInp.condInput, EXEC_LOCALLY_KW, "");
        }
    }
    else if (destRemoteFlag == REMOTE_ZONE_HOST ||
             (srcRemoteFlag == LOCAL_HOST && destRemoteFlag != LOCAL_HOST)) {
        // Destination: remote zone OR different host in local zone
        // Source: local zone
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_REM_OPR );
        if ( L1desc[_destination_l1descInx].dataObjInp->numThreads > 0 ) {
            int status = preProcParaPut( rsComm, _destination_l1descInx, &portalOprOut );
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaPut error for %s",
                        __FUNCTION__,
                        L1desc[source_l1descInx].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = _destination_l1descInx;
        }
        if ( srcRemoteFlag == LOCAL_HOST ) {
            addKeyVal( &dataCopyInp.dataOprInp.condInput, EXEC_LOCALLY_KW, "" );
        }
    }
    else if (srcRemoteFlag == REMOTE_ZONE_HOST ||
             (srcRemoteFlag != LOCAL_HOST && destRemoteFlag == LOCAL_HOST)) {
        // Destination: local zone
        // Source: remote zone OR different host in local zone
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_LOCAL_OPR );
        if ( L1desc[_destination_l1descInx].dataObjInp->numThreads > 0 ) {
            int status = preProcParaGet( rsComm, source_l1descInx, &portalOprOut );
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaGet error for %s",
                        __FUNCTION__,
                        L1desc[source_l1descInx].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = source_l1descInx;
        }
        if ( destRemoteFlag == LOCAL_HOST ) {
            addKeyVal( &dataCopyInp.dataOprInp.condInput, EXEC_LOCALLY_KW, "" );
        }
    }
    else {
        /* remote to remote */
        initDataOprInp( &dataCopyInp.dataOprInp, _destination_l1descInx, COPY_TO_LOCAL_OPR );
        if (L1desc[_destination_l1descInx].dataObjInp->numThreads > 0) {
            int status = preProcParaGet(rsComm, source_l1descInx, &portalOprOut);
            if (status < 0 || !portalOprOut) {
                rodsLog(LOG_NOTICE,
                        "%s: preProcParaGet error for %s",
                        __FUNCTION__,
                        L1desc[source_l1descInx].dataObjInfo->objPath );
                free( portalOprOut );
                return status;
            }
            dataCopyInp.portalOprOut = *portalOprOut;
        }
        else {
            dataCopyInp.portalOprOut.l1descInx = source_l1descInx;
        }
    }

    if (getValByKey(&L1desc[_destination_l1descInx].dataObjInp->condInput, NO_CHK_COPY_LEN_KW)) {
        addKeyVal(&dataCopyInp.dataOprInp.condInput, NO_CHK_COPY_LEN_KW, "");
        if (L1desc[_destination_l1descInx].dataObjInp->numThreads > 1) {
            L1desc[_destination_l1descInx].dataObjInp->numThreads = 1;
            L1desc[source_l1descInx].dataObjInp->numThreads = 1;
            dataCopyInp.portalOprOut.numThreads = 1;
        }
    }

    int status = rsDataCopy(rsComm, &dataCopyInp);
    if (status >= 0 && portalOprOut && L1desc[_destination_l1descInx].dataObjInp) {
        /* update numThreads since it could be changed by remote server */
        L1desc[_destination_l1descInx].dataObjInp->numThreads = portalOprOut->numThreads;
    }
    free(portalOprOut);
    return status;
} // dataObjCopy

int unbunAndStageBunfileObj(rsComm_t* rsComm, const char* bunfileObjPath, char** outCacheRescName) {

    /* query the bundle dataObj */
    dataObjInp_t dataObjInp{};
    rstrcpy( dataObjInp.objPath, bunfileObjPath, MAX_NAME_LEN );

    dataObjInfo_t *bunfileObjInfoHead{};
    int status = getDataObjInfo( rsComm, &dataObjInp, &bunfileObjInfoHead, NULL, 1 );
    if ( status < 0 ) {
        rodsLog( LOG_ERROR,
                 "unbunAndStageBunfileObj: getDataObjInfo of bunfile %s failed.stat=%d",
                 dataObjInp.objPath, status );
        return status;
    }
    status = _unbunAndStageBunfileObj( rsComm, &bunfileObjInfoHead, &dataObjInp.condInput,
                                       outCacheRescName, 0 );

    freeAllDataObjInfo( bunfileObjInfoHead );

    return status;
} // unbunAndStageBunfileObj

int _unbunAndStageBunfileObj(
    rsComm_t* rsComm,
    dataObjInfo_t** bunfileObjInfoHead,
    keyValPair_t * condInput,
    char** outCacheRescName,
    const int rmBunCopyFlag) {

    dataObjInp_t dataObjInp{};
    bzero( &dataObjInp.condInput, sizeof( dataObjInp.condInput ) );
    rstrcpy( dataObjInp.objPath, ( *bunfileObjInfoHead )->objPath, MAX_NAME_LEN );
    int status = sortObjInfoForOpen( bunfileObjInfoHead, condInput, 0 );

    addKeyVal( &dataObjInp.condInput, RESC_HIER_STR_KW, ( *bunfileObjInfoHead )->rescHier );
    if ( status < 0 ) {
        return status;
    }

    if (outCacheRescName) {
        *outCacheRescName = ( *bunfileObjInfoHead )->rescName;
    }

    addKeyVal(&dataObjInp.condInput, BUN_FILE_PATH_KW, (*bunfileObjInfoHead)->filePath);
    if ( rmBunCopyFlag > 0 ) {
        addKeyVal( &dataObjInp.condInput, RM_BUN_COPY_KW, "" );
    }
    if (!std::string_view{(*bunfileObjInfoHead)->dataType}.empty()) {
        addKeyVal(&dataObjInp.condInput, DATA_TYPE_KW, (*bunfileObjInfoHead)->dataType);
    }
    status = _rsUnbunAndRegPhyBunfile(rsComm, &dataObjInp, (*bunfileObjInfoHead)->rescName);

    return status;
} // _unbunAndStageBunfileObj
