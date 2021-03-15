#include "apiNumber.h"
#include "dataObjClose.h"
#include "dataObjCreate.h"
#include "dataObjCreateAndStat.h"
#include "dataObjInpOut.h"
#include "dataObjLock.h"
#include "dataObjOpen.h"
#include "dataObjOpenAndStat.h"
#include "dataObjOpr.hpp"
#include "dataObjRepl.h"
#include "dataObjUnlink.h"
#include "fileCreate.h"
#include "fileOpen.h"
#include "getRemoteZoneResc.h"
#include "getRescQuota.h"
#include "icatHighLevelRoutines.hpp"
#include "irods_exception.hpp"
#include "irods_get_l1desc.hpp"
#include "irods_linked_list_iterator.hpp"
#include "irods_resource_types.hpp"
#include "objInfo.h"
#include "objMetaOpr.hpp"
#include "physPath.hpp"
#include "rcGlobalExtern.h"
#include "rcMisc.h"
#include "regDataObj.h"
#include "regReplica.h"
#include "resource.hpp"
#include "rodsErrorTable.h"
#include "rodsLog.h"
#include "rsDataObjClose.hpp"
#include "rsDataObjCreate.hpp"
#include "rsDataObjOpen.hpp"
#include "rsDataObjRepl.hpp"
#include "rsDataObjUnlink.hpp"
#include "rsFileCreate.hpp"
#include "rsFileOpen.hpp"
#include "rsGetRescQuota.hpp"
#include "rsGlobalExtern.hpp"
#include "rsModDataObjMeta.hpp"
#include "rsObjStat.hpp"
#include "rsPhyPathReg.hpp"
#include "rsRegDataObj.hpp"
#include "rsRegReplica.hpp"
#include "rsSubStructFileCreate.hpp"
#include "rsSubStructFileOpen.hpp"
#include "rsUnregDataObj.hpp"
#include "specColl.hpp"
#include "subStructFileCreate.h"
#include "subStructFileOpen.h"

// =-=-=-=-=-=-=-
#include "finalize_utilities.hpp"
#include "irods_at_scope_exit.hpp"
#include "irods_hierarchy_parser.hpp"
#include "irods_log.hpp"
#include "irods_resource_backport.hpp"
#include "irods_resource_redirect.hpp"
#include "irods_server_api_call.hpp"
#include "irods_server_properties.hpp"
#include "irods_stacktrace.hpp"
#include "key_value_proxy.hpp"
#include "logical_locking.hpp"
#include "replica_access_table.hpp"
#include "replica_state_table.hpp"
#include "scoped_privileged_client.hpp"

#define IRODS_FILESYSTEM_ENABLE_SERVER_SIDE_API
#include "filesystem.hpp"

#define IRODS_QUERY_ENABLE_SERVER_SIDE_API
#include "irods_query.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include <fmt/format.h>

#include <chrono>
#include <stdexcept>

#include <sys/types.h>
#include <unistd.h>

namespace
{
    // clang-format off
    namespace ill           = irods::logical_locking;
    namespace fs            = irods::experimental::filesystem;
    namespace id            = irods::experimental::data_object;
    namespace ir            = irods::experimental::replica;
    namespace rat           = irods::experimental::replica_access_table;
    namespace rst           = irods::replica_state_table;

    using replica_proxy     = irods::experimental::replica::replica_proxy<DataObjInfo>;
    using data_object_proxy = irods::experimental::data_object::data_object_proxy<DataObjInfo>;
    using log               = irods::experimental::log;
    // clang-format on

    // Instructs how "update_replica_access_table" should update the
    // replica access table.
    enum class update_operation
    {
        create,
        update
    };

    void update_replica_access_table(rsComm_t& _conn,
                                     update_operation _op,
                                     int _l1desc_index,
                                     const dataObjInp_t& _input)
    {
        const fs::path p = _input.objPath;
        const irods::experimental::key_value_proxy kvp{_input.condInput};

        rat::data_id_type data_id;
        rat::replica_number_type replica_number;

        try {
            const auto gql = fmt::format("select DATA_ID, DATA_REPL_NUM "
                                         "where"
                                         " COLL_NAME = '{}' and"
                                         " DATA_NAME = '{}' and"
                                         " DATA_RESC_HIER = '{}'",
                                         p.parent_path().c_str(),
                                         p.object_name().c_str(),
                                         kvp.at(RESC_HIER_STR_KW).value());

            for (auto&& row : irods::query{&_conn, gql}) {
                data_id = std::stoull(row[0]);
                replica_number = std::stoul(row[1]);
            }
        }
        catch (const std::out_of_range&) {
            THROW(SYS_INTERNAL_ERR, "Could not convert string to integer");
        }

        auto& l1desc = L1desc[_l1desc_index];

        try {
            if (update_operation::create == _op) {
                l1desc.replica_token = rat::create_new_entry(data_id, replica_number, getpid());
            }
            else {
                auto token = kvp.at(REPLICA_TOKEN_KW).value();
                rat::append_pid(token.data(), data_id, replica_number, getpid());
                l1desc.replica_token = token;
            }
        }
        catch (const rat::replica_access_table_error& e) {
            log::api::error(e.what());
            THROW(SYS_INTERNAL_ERR, e.what());
        }
    } // update_replica_access_table

    int change_replica_status(rsComm_t& rsComm, dataObjInp_t& dataObjInp, int new_replica_status)
    {
        {
            const auto l = {GOOD_REPLICA, INTERMEDIATE_REPLICA, STALE_REPLICA};
            if (std::none_of(std::begin(l), std::end(l), [x = new_replica_status](auto y) { return x == y; })) {
                return SYS_INVALID_INPUT_PARAM;
            }
        }

        const irods::experimental::key_value_proxy src{dataObjInp.condInput};
        auto resc_hier = src.at(RESC_HIER_STR_KW).value();

        dataObjInfo_t info{};
        rstrcpy(info.objPath, dataObjInp.objPath, MAX_NAME_LEN);
        rstrcpy(info.rescHier, resc_hier.data(), MAX_NAME_LEN);

        auto [dst, dst_lm] = irods::experimental::make_key_value_proxy({{REPL_STATUS_KW, std::to_string(new_replica_status)}});
        if (src.contains(ADMIN_KW)) {
            dst[ADMIN_KW] = "";
        }

        modDataObjMeta_t inp{};
        inp.dataObjInfo = &info;
        inp.regParam = dst.get();

        return rsModDataObjMeta(&rsComm, &inp);
    } // change_replica_status

    void enable_creation_of_additional_replicas(rsComm_t& _comm)
    {
        // rxDataObjOpen has the freedom to create replicas on demand. To enable this,
        // it must always set the following flag. This special flag instructs rsPhyPathReg
        // to register a new replica if an existing replica already exists.
        irods::experimental::key_value_proxy{_comm.session_props}[REG_REPL_KW] = "";
    } // enable_creation_of_additional_replicas

    int close_replica(rsComm_t& conn, int l1desc_index)
    {
        openedDataObjInp_t input{};
        input.l1descInx = l1desc_index;
        return rsDataObjClose(&conn, &input);
    } // close_replica

    int l3CreateByObjInfo(
        rsComm_t* rsComm,
        dataObjInp_t* dataObjInp,
        dataObjInfo_t* dataObjInfo ) {

        int chkType = getchkPathPerm( rsComm, dataObjInp, dataObjInfo );
        if ( chkType == DISALLOW_PATH_REG ) {
            return PATH_REG_NOT_ALLOWED;
        }

        fileCreateInp_t fileCreateInp{};
        rstrcpy(fileCreateInp.resc_name_,    dataObjInfo->rescName, MAX_NAME_LEN);
        rstrcpy(fileCreateInp.resc_hier_,    dataObjInfo->rescHier, MAX_NAME_LEN);
        rstrcpy(fileCreateInp.objPath,       dataObjInfo->objPath,  MAX_NAME_LEN);
        rstrcpy(fileCreateInp.fileName,      dataObjInfo->filePath, MAX_NAME_LEN);
        rstrcpy(fileCreateInp.in_pdmo,       dataObjInfo->in_pdmo,  MAX_NAME_LEN );
        fileCreateInp.mode = getFileMode(dataObjInp);
        copyKeyVal(&dataObjInfo->condInput, &fileCreateInp.condInput);

        if ( chkType == NO_CHK_PATH_PERM ) {
            fileCreateInp.otherFlags |= NO_CHK_PERM_FLAG;
        }

        //loop until we find a valid filename
        int retryCnt = 0;
        int l3descInx;
        do {
            fileCreateOut_t* create_out{};
            l3descInx = rsFileCreate(rsComm, &fileCreateInp, &create_out);

            // update the dataObjInfo with the potential changes made by the resource - hcj
            if (create_out) {
                rstrcpy(dataObjInfo->rescHier, fileCreateInp.resc_hier_, MAX_NAME_LEN);
                rstrcpy(dataObjInfo->filePath, create_out->file_name, MAX_NAME_LEN);
                free(create_out);
            }

            //update the filename in case of a retry
            rstrcpy(fileCreateInp.fileName, dataObjInfo->filePath, MAX_NAME_LEN);
            retryCnt++;
        }
        while ( l3descInx < 0 && getErrno( l3descInx ) == EEXIST &&
                resolveDupFilePath( rsComm, dataObjInfo, dataObjInp ) >= 0 &&
                l3descInx <= 2 && retryCnt < 100 );
        clearKeyVal( &fileCreateInp.condInput );
        return l3descInx;
    } // l3CreateByObjInfo

    auto create_new_replica(rsComm_t& _comm, dataObjInp_t& _inp, DataObjInfo* _existing_replica_list) -> int
    {
        const auto special_collection_type = irods::get_special_collection_type_for_data_object(_comm, _inp);
        if (special_collection_type < 0) {
            return special_collection_type;
        }

        switch (special_collection_type) {
            case NO_SPEC_COLL:
                // This is not a special collection - continue down the normal path
                break;

            case LINKED_COLL:
                // Linked collection should have been translated by this point - return error.
                return SYS_COLL_LINK_PATH_ERR;

            default:
                // This is a special collection so it has special creation logic
                return irods::data_object_create_in_special_collection(&_comm, _inp);
        }

        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

        std::string_view hierarchy = cond_input.at(RESC_HIER_STR_KW).value();

        // conjuring a brand new data object info - intentionally take ownership of allocated struct
        // NOTE: all of this information is free'd and overwritten by the structure in the rsPhyPathReg
        // call, but is required to inform the database about the replica we are creating.
        auto [new_replica, lm] = ir::make_replica_proxy();
        lm.release();
        new_replica.logical_path(_inp.objPath);
        new_replica.replica_status(INTERMEDIATE_REPLICA);
        new_replica.hierarchy(hierarchy);
        new_replica.resource_id(resc_mgr.hier_to_leaf_id(new_replica.hierarchy()));
        new_replica.resource(irods::hierarchy_parser{new_replica.hierarchy().data()}.first_resc());
        new_replica.mode(std::to_string(_inp.createMode));
        new_replica.type(cond_input.contains(DATA_TYPE_KW) ? cond_input.at(DATA_TYPE_KW).value() : GENERIC_DT_STR);

        if (cond_input.contains(DATA_ID_KW)) {
            new_replica.data_id(std::atoll(cond_input.at(DATA_ID_KW).value().data()));
        }

        if (cond_input.contains(FILE_PATH_KW)) {
            new_replica.physical_path(cond_input.at(FILE_PATH_KW).value());
        }

        cond_input[OPEN_TYPE_KW] = std::to_string(CREATE_TYPE);
        const int l1_index = irods::populate_L1desc_with_inp(_inp, *new_replica.get(), _inp.dataSize);
        auto& l1desc = L1desc[l1_index];

        if (const int ec = getFilePathName(&_comm, new_replica.get(), l1desc.dataObjInp); ec < 0) {
            freeL1desc(l1_index);

            THROW(ec, fmt::format(
                "[{}] - failed to get file path name for [{]] on hierarchy [{}]",
                __FUNCTION__, new_replica.logical_path(), new_replica.hierarchy()));
        }

        auto l1_cond_input = irods::experimental::make_key_value_proxy(l1desc.dataObjInp->condInput);
        l1_cond_input[REGISTER_AS_INTERMEDIATE_KW] = "";
        l1_cond_input[FILE_PATH_KW] = new_replica.physical_path();
        l1_cond_input[DATA_SIZE_KW] = std::to_string(0);

        // TODO: throw if locked

        if (const int ec = rsPhyPathReg(&_comm, l1desc.dataObjInp); ec < 0) {
            THROW(ec, fmt::format("[{}] - failed in rsPhyPathReg", __FUNCTION__));
        }

        if (cond_input.contains(KEY_VALUE_PASSTHROUGH_KW)) {
            auto info_cond_input = irods::experimental::make_key_value_proxy(L1desc[l1_index].dataObjInfo->condInput);
            info_cond_input[KEY_VALUE_PASSTHROUGH_KW] = cond_input.at(KEY_VALUE_PASSTHROUGH_KW).value();
        }

        // TODO: new_replica is free'd in rsPhyPathReg, making the proxy unusable
        // Need to find a better way to populate the information going in or coming out so that the interface makes more sense
        auto registered_replica = ir::make_replica_proxy(*l1desc.dataObjInfo);

        if (!l1desc.dataObjInfo->specColl) {
            if (rst::contains(registered_replica.data_id())) {
                if (_existing_replica_list) {
                    auto obj = id::make_data_object_proxy(*_existing_replica_list);
                    obj.add_replica(*registered_replica.get());
                }
                rst::insert(registered_replica);
            }
            else {
                auto obj = id::make_data_object_proxy(*registered_replica.get());
                rst::insert(obj);
            }

            if (const int lock_ec = ill::lock_and_publish(_comm, registered_replica.data_id(), registered_replica.replica_number(), ill::lock_type::write); lock_ec < 0) {
                irods::log(LOG_NOTICE, fmt::format(
                    "Failed to lock data object on create "
                    "[error_code={}, path={}, hierarchy={}]",
                    lock_ec, _inp.objPath, hierarchy));

                registered_replica.replica_status(STALE_REPLICA);

                rst::update(registered_replica.data_id(), registered_replica.replica_number(),
                    nlohmann::json{{"data_is_dirty", std::to_string(registered_replica.replica_status())}});

                if (const int ec = ill::unlock_and_publish(_comm, registered_replica.data_id(), registered_replica.replica_number(), ill::restore_status); ec < 0) {
                    irods::log(LOG_NOTICE, fmt::format(
                        "Failed to unlock data object on create failure "
                        "[error_code={}, path={}, hierarchy={}]",
                        ec, _inp.objPath, hierarchy));

                    return ec;
                }

                return lock_ec;
            }
        }

        if (cond_input.contains(NO_OPEN_FLAG_KW)) {
            return l1_index;
        }

        const auto l3_index = l3CreateByObjInfo(&_comm, l1desc.dataObjInp, l1desc.dataObjInfo);
        if (l3_index < 0) {
            irods::log(LOG_NOTICE, fmt::format(
                "[{}:{}] - l3Create of [{}] failed, status = [{}]",
                __FUNCTION__, __LINE__, registered_replica.physical_path(), l3_index));

            registered_replica.replica_status(STALE_REPLICA);

            rst::update(registered_replica.data_id(), registered_replica.replica_number(),
                nlohmann::json{{"data_is_dirty", std::to_string(registered_replica.replica_status())}});

            if (const int ec = ill::unlock_and_publish(_comm, registered_replica.data_id(), registered_replica.replica_number(), ill::restore_status); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "Failed to unlock data object on physical file create failure "
                    "[error_code={}, path={}, hierarchy={}]",
                    ec, _inp.objPath, hierarchy));
            }

            if (const int ec = dataObjUnlinkS(&_comm, l1desc.dataObjInp, l1desc.dataObjInfo); ec < 0) {
                irods::log(LOG_ERROR, fmt::format(
                    "[{}:{}] - dataObjUnlinkS failed for [{}] with [{}]",
                    __FUNCTION__, __LINE__, registered_replica.physical_path(), ec));
            }

            freeL1desc(l1_index);

            return l3_index;
        }

        L1desc[l1_index].l3descInx = l3_index;

        try {
            update_replica_access_table(_comm, update_operation::create, l1_index, _inp);
        }
        catch (const irods::exception& e) {
            irods::log(LOG_ERROR, fmt::format(
                "Could not update replica access table for newly created data object. "
                "Closing data object and setting replica status to stale. "
                "[path={}, error_code={}, exception={}]",
                _inp.objPath, e.code(), e.client_display_what()));

            constexpr auto preserve_rst = false;
            if (const auto ec = irods::close_replica_without_catalog_update(_comm, l1_index, preserve_rst); ec < 0) {
                auto hier = irods::experimental::key_value_proxy{_inp.condInput}[RESC_HIER_STR_KW].value();
                irods::log(LOG_ERROR, fmt::format(
                    "Failed to close replica [error_code={}, path={}, hierarchy={}]",
                    ec, _inp.objPath, hier));
                return ec;
            }

            // TODO: unlock
            if (const auto ec = change_replica_status(_comm, _inp, STALE_REPLICA); ec < 0) {
                auto hier = irods::experimental::key_value_proxy{_inp.condInput}[RESC_HIER_STR_KW].value();
                log::api::error("Failed to set the replica's replica status to stale "
                                   "[error_code={}, path={}, hierarchy={}]",
                                   ec, _inp.objPath, hier);
                return ec;
            }

            return e.code();
        }

        return l1_index;
    } // create_new_replica

    int stage_bundled_data_to_cache_directory(rsComm_t * rsComm, dataObjInfo_t **subfileObjInfoHead)
    {
        dataObjInfo_t *dataObjInfoHead = *subfileObjInfoHead;
        char* cacheRescName{};
        int status = unbunAndStageBunfileObj(
                        rsComm,
                        dataObjInfoHead->filePath,
                        &cacheRescName);
        if ( status < 0 ) {
            return status;
        }

        /* query the bundle dataObj */
        dataObjInp_t dataObjInp{};
        addKeyVal( &dataObjInp.condInput, RESC_NAME_KW, cacheRescName );
        rstrcpy( dataObjInp.objPath, dataObjInfoHead->objPath, MAX_NAME_LEN );

        dataObjInfo_t* cacheObjInfo{};
        status = getDataObjInfo( rsComm, &dataObjInp, &cacheObjInfo, NULL, 0 );
        clearKeyVal( &dataObjInp.condInput );
        if ( status < 0 ) {
            rodsLog( LOG_ERROR,
                     "%s: getDataObjInfo of subfile %s failed.stat=%d",
                     __FUNCTION__, dataObjInp.objPath, status );
            return status;
        }
        /* que the cache copy at the top */
        queDataObjInfo( subfileObjInfoHead, cacheObjInfo, 0, 1 );
        return status;
    } // stage_bundled_data_to_cache_directory

    int l3Open(rsComm_t *rsComm, int l1descInx)
    {
        dataObjInfo_t* dataObjInfo = L1desc[l1descInx].dataObjInfo;
        if (!dataObjInfo) {
            return SYS_INTERNAL_NULL_INPUT_ERR;
        }

        std::string location{};
        irods::error ret = irods::get_loc_for_hier_string( dataObjInfo->rescHier, location );
        if ( !ret.ok() ) {
            irods::log(LOG_ERROR, fmt::format(
                "{} - failed in get_loc_for_hier_string:[{}]; ec:[{}]",
                __FUNCTION__, ret.result(), ret.code()));
            return ret.code();
        }

        if ( getStructFileType( dataObjInfo->specColl ) >= 0 ) {
            subFile_t subFile{};
            rstrcpy( subFile.subFilePath, dataObjInfo->subPath, MAX_NAME_LEN );
            rstrcpy( subFile.addr.hostAddr, location.c_str(), NAME_LEN );
            subFile.specColl = dataObjInfo->specColl;
            subFile.mode = getFileMode( L1desc[l1descInx].dataObjInp );
            subFile.flags = getFileFlags( l1descInx );
            return rsSubStructFileOpen( rsComm, &subFile );
        }

        fileOpenInp_t fileOpenInp{};
        rstrcpy( fileOpenInp.resc_name_, dataObjInfo->rescName, MAX_NAME_LEN );
        rstrcpy( fileOpenInp.resc_hier_, dataObjInfo->rescHier, MAX_NAME_LEN );
        rstrcpy( fileOpenInp.objPath,    dataObjInfo->objPath, MAX_NAME_LEN );
        rstrcpy( fileOpenInp.addr.hostAddr,  location.c_str(), NAME_LEN );
        rstrcpy( fileOpenInp.fileName, dataObjInfo->filePath, MAX_NAME_LEN );
        fileOpenInp.mode = getFileMode(L1desc[l1descInx].dataObjInp);
        fileOpenInp.flags = getFileFlags(l1descInx);
        rstrcpy( fileOpenInp.in_pdmo, dataObjInfo->in_pdmo, MAX_NAME_LEN );

        copyKeyVal(&dataObjInfo->condInput, &fileOpenInp.condInput);

        const int l3descInx = rsFileOpen(rsComm, &fileOpenInp);
        clearKeyVal( &fileOpenInp.condInput );
        return l3descInx;
    } // l3Open

    auto open_replica(RsComm& _comm, DataObjInp& _inp, replica_proxy& _replica) -> int
    {
        copyKeyVal(&_inp.condInput, _replica.cond_input().get());

        /* the size was set to -1 because we don't know the target size.
         * For copy and replicate, the calling routine should modify this
         * dataSize */
        const int l1_index = irods::populate_L1desc_with_inp(_inp, *_replica.get(), -1);

        const auto open_for_write = getWriteFlag(_inp.openFlags);
        if (open_for_write) {
            L1desc[l1_index].replStatus = INTERMEDIATE_REPLICA;
        }

        L1desc[l1_index].openType = open_for_write ? OPEN_FOR_WRITE_TYPE : OPEN_FOR_READ_TYPE;

        if (_replica.cond_input().contains(NO_OPEN_FLAG_KW)) {
            /* don't actually physically open the file */
            return l1_index;
        }

        if (_replica.cond_input().contains(PHYOPEN_BY_SIZE_KW)) {
            try {
                const auto single_buffer_size = irods::get_advanced_setting<const int>(irods::CFG_MAX_SIZE_FOR_SINGLE_BUFFER) * 1024 * 1024;
                if (_replica.size() <= single_buffer_size &&
                    (UNKNOWN_FILE_SZ != _replica.size() || _replica.cond_input().contains(DATA_INCLUDED_KW))) {
                    return l1_index;
                }
            }
            catch (const irods::exception& e) {
                freeL1desc(l1_index);
                throw;
            }
        }

        const int l3_index = l3Open(&_comm, l1_index);
        if (l3_index <= 0) {
            freeL1desc(l1_index);
            THROW(l3_index, fmt::format(
                "[{}] - l3Open of {} failed, status = {}",
                __FUNCTION__, _inp.objPath, l3_index));
        }

        auto& fd = L1desc[l1_index];
        fd.l3descInx = l3_index;

        // Set the size of the data object to zero in the catalog if the file was truncated.
        // It is important that the catalog reflect truncation immediately because operations
        // following the open may depend on the size of the data object.
        //
        // TODO: do not touch the catalog -- update the structure and use this in lock_data_object
        if (fd.dataObjInp->openFlags & O_TRUNC) {
            if (const auto access_mode = (fd.dataObjInp->openFlags & O_ACCMODE);
                access_mode == O_WRONLY || access_mode == O_RDWR)
            {
                dataObjInfo_t info{};
                rstrcpy(info.objPath, fd.dataObjInp->objPath, MAX_NAME_LEN);
                rstrcpy(info.rescHier, fd.dataObjInfo->rescHier, MAX_NAME_LEN);

                keyValPair_t kvp{};
                addKeyVal(&kvp, DATA_SIZE_KW, "0");
                if (getValByKey(&_inp.condInput, ADMIN_KW)) {
                    addKeyVal(&kvp, ADMIN_KW, "");
                }

                modDataObjMeta_t input{};
                input.dataObjInfo = &info;
                input.regParam = &kvp;

                if (const auto ec = rsModDataObjMeta(&_comm, &input); ec != 0) {
                    THROW(ec, fmt::format(
                        "{}: Could not update size of data object [status = {}, path = {}]",
                        __FUNCTION__, ec, _inp.objPath));
                }

                fd.dataSize = 0;

                if (fd.dataObjInfo) {
                    fd.dataObjInfo->dataSize = 0;
                }
            }
        }

        return l1_index;
    } // open_replica

    auto get_data_object_info_for_open(RsComm& _comm, DataObjInp& _inp)
        -> std::tuple<DataObjInfo*, std::string>
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

        std::string hierarchy_for_open{};
        if (cond_input.contains(RESC_HIER_STR_KW)) {
            hierarchy_for_open = cond_input.at(RESC_HIER_STR_KW).value().data();
        }
        // If the client specified a leaf resource, then discover the hierarchy and
        // store it in the keyValPair_t. This instructs the iRODS server to create
        // the replica at the specified resource if it does not exist.
        else if (cond_input.contains(LEAF_RESOURCE_NAME_KW)) {
            auto leaf = cond_input.at(LEAF_RESOURCE_NAME_KW).value();
            bool is_coord_resc = false;

            if (const auto err = resc_mgr.is_coordinating_resource(leaf.data(), is_coord_resc); !err.ok()) {
                THROW(err.code(), err.result());
            }

            // Leaf resources cannot be coordinating resources. This essentially checks
            // if the resource has any child resources which is exactly what we're interested in.
            if (is_coord_resc) {
                THROW(USER_INVALID_RESC_INPUT, fmt::format("[{}] is not a leaf resource.", leaf));
            }

            if (const auto err = resc_mgr.get_hier_to_root_for_resc(leaf.data(), hierarchy_for_open); !err.ok()) {
                THROW(err.code(), err.result());
            }
        }

        // Get replica information for data object, resolving hierarchy if necessary
        dataObjInfo_t* info_head{};

        if (hierarchy_for_open.empty()) {
            try {
                irods::file_object_ptr file_obj;
                std::tie(file_obj, hierarchy_for_open) = irods::resolve_resource_hierarchy(
                    (_inp.openFlags & O_CREAT) ? irods::CREATE_OPERATION : irods::OPEN_OPERATION,
                    &_comm, _inp, &info_head);
            }
            catch (const irods::exception& e) {
                // If the data object does not exist, then the exception will contain
                // an error code of CAT_NO_ROWS_FOUND.
                if (e.code() == CAT_NO_ROWS_FOUND) {
                    THROW(OBJ_PATH_DOES_NOT_EXIST, fmt::format(
                        "Data object or replica does not exist [error_code={}, path={}].",
                        e.code(), _inp.objPath));
                }

                throw;
            }
        }
        else {
            irods::file_object_ptr file_obj{new irods::file_object()};
            irods::error fac_err = irods::file_object_factory(&_comm, &_inp, file_obj, &info_head);
            if (!fac_err.ok() && CAT_NO_ROWS_FOUND != fac_err.code()) {
                irods::log(fac_err);
            }
        }

        if (!cond_input.contains(RESC_HIER_STR_KW)) {
            cond_input[RESC_HIER_STR_KW] = hierarchy_for_open;
        }

        cond_input[SELECTED_HIERARCHY_KW] = hierarchy_for_open;

        return {info_head, hierarchy_for_open};
    } // get_data_object_info_for_open

    auto apply_static_pep_data_obj_open_pre(RsComm& _comm, DataObjInp& _inp, DataObjInfo** _info_head) -> int
    {
        ruleExecInfo_t rei;
        initReiWithDataObjInp( &rei, &_comm, &_inp );
        rei.doi = *_info_head;

        // make resource properties available as rule session variables
        irods::get_resc_properties_as_kvp(rei.doi->rescHier, rei.condInputData);

        int status = applyRule( "acPreprocForDataObjOpen", NULL, &rei, NO_SAVE_REI );
        clearKeyVal(rei.condInputData);
        free(rei.condInputData);

        if (status < 0) {
            if (rei.status < 0) {
                status = rei.status;
            }

            irods::log(LOG_ERROR, fmt::format(
                "{}:acPreprocForDataObjOpen error for {},stat={}",
                __FUNCTION__, _inp.objPath, status));

            return status;
        }

        *_info_head = rei.doi;
        return rei.status;
    } // apply_static_pep_data_obj_open_pre

    auto leaf_resource_is_bundleresc(const std::string_view _hierarchy)
    {
        std::string resc_class{};
        const irods::error prop_err = irods::get_resource_property<std::string>(
            resc_mgr.hier_to_leaf_id(_hierarchy), irods::RESOURCE_CLASS, resc_class);
        return prop_err.ok() && irods::RESOURCE_CLASS_BUNDLE == resc_class;
    } // leaf_resource_is_bundleresc

    auto throw_if_data_object_is_locked(
        const DataObjInp& _inp,
        const ir::replica_proxy_t& _replica) -> void
    {
        if (_replica.locked()) {
            switch (_replica.replica_status()) {
                case READ_LOCKED:
                    if (const auto opening_for_read = !getWriteFlag(_inp.openFlags); opening_for_read) {
                        break;
                    }
                    [[fallthrough]];

                case WRITE_LOCKED:
                    THROW(LOCKED_DATA_OBJECT_ACCESS, fmt::format(
                        "[{}:{}] - data object [{}] is locked; open denied",
                        __FUNCTION__, __LINE__, _replica.logical_path()));

                default:
                    // This is a terrible, terrible error
                    THROW(SYS_INTERNAL_ERR, fmt::format(
                        "[{}:{}] - replica status [{}] is not a lock",
                        __FUNCTION__, __LINE__, _replica.replica_status()));
            }
        }

        // If the catalog information indicates that the selected replica is intermediate, check
        // to see if the provided replica token will be accepted by the replica access table.
        // If not, the open request is disallowed because multiple opens of the same replica are
        // not allowed without a valid replica token.
        const auto replica_access_granted = [&_replica, &_inp]() -> bool
        {
            if (_replica.at_rest()) {
                return true;
            }

            const auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

            if (!cond_input.contains(REPLICA_TOKEN_KW)) {
                return false;
            }

            auto token = cond_input.at(REPLICA_TOKEN_KW).value();
            return rat::contains(token.data(), _replica.data_id(), _replica.replica_number());
        }();

        if (!replica_access_granted) {
            THROW(INTERMEDIATE_REPLICA_ACCESS, fmt::format(
                "[{}:{}] - selected replica is an intermediate replica",
                __FUNCTION__, __LINE__));
        }
    } // throw_if_data_object_is_locked

    auto remote_open(rodsServerHost& _server_host, DataObjInp& _inp) -> int
    {
        OpenStat* stat{};
        const auto free_stat = irods::at_scope_exit{[&stat] { if (stat) std::free(stat); }};

        const int remoteL1descInx = rcDataObjOpenAndStat(_server_host.conn, &_inp, &stat);
        if (remoteL1descInx < 0) {
            return remoteL1descInx;
        }

        return allocAndSetL1descForZoneOpr(remoteL1descInx, &_inp, &_server_host, stat);
    } // remote_open

    int rsDataObjOpen_impl(rsComm_t *rsComm, dataObjInp_t *dataObjInp)
    {
        rodsServerHost_t* rodsServerHost{};
        const int remoteFlag = getAndConnRemoteZone(rsComm, dataObjInp, &rodsServerHost, REMOTE_OPEN);
        if (remoteFlag < 0) {
            return remoteFlag;
        }
        else if (REMOTE_HOST == remoteFlag) {
            return remote_open(*rodsServerHost, *dataObjInp);
        }

        enable_creation_of_additional_replicas(*rsComm);

        auto cond_input = irods::experimental::key_value_proxy(dataObjInp->condInput);

        // TODO: remove lock fd
        int lockFd = -1;

        const auto unlock_data_obj{[&]() {
            char fd_string[NAME_LEN]{};
            snprintf( fd_string, sizeof( fd_string ), "%-d", lockFd );
            cond_input[LOCK_FD_KW] = fd_string;
            irods::server_api_call(
                DATA_OBJ_UNLOCK_AN,
                rsComm,
                dataObjInp,
                NULL,
                ( void** ) NULL,
                NULL );
        }};
        // end lock fd section

        DataObjInfo* info_head{};
        std::string hierarchy{};

        try {
            std::tie(info_head, hierarchy) = get_data_object_info_for_open(*rsComm, *dataObjInp);
        }
        catch (const irods::exception& e) {
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.client_display_what()));
            return e.code();
        }
        catch (const std::exception& e) {
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.what()));
            return SYS_LIBRARY_ERROR;
        }
        catch (...) {
            irods::log(LOG_ERROR, fmt::format("[{}] - unknown error has occurred.", __FUNCTION__));
            return SYS_UNKNOWN_ERROR;
        }

        // TODO: remove lock fd
        if (cond_input.contains(LOCK_TYPE_KW) && cond_input.at(LOCK_TYPE_KW).value().data()) {
            rodsLog(LOG_DEBUG, "[%s:%d] - locking file with type [%s]",
                __FUNCTION__, __LINE__, getValByKey(&dataObjInp->condInput, LOCK_TYPE_KW));

            lockFd = irods::server_api_call(
                         DATA_OBJ_LOCK_AN,
                         rsComm, dataObjInp,
                         NULL, (void**)NULL, NULL);

            if (lockFd <= 0) {
                rodsLog(LOG_ERROR, "%s: lock error for %s. lockType = %s, lockFd: %d",
                        __FUNCTION__, dataObjInp->objPath, cond_input.at(LOCK_TYPE_KW).value().data(), lockFd );
                return lockFd;
            }

            /* rm it so it won't be done again causing deadlock */
            cond_input.erase(LOCK_TYPE_KW);
        }
        // end lock fd section

        try {
            // determine if the replica described by the inputs exists
            if (dataObjInp->openFlags & O_CREAT) {
                const auto creating_new_replica = [&info_head, &hierarchy]() -> bool
                {
                    return !info_head ||
                           !id::find_replica(id::make_data_object_proxy(*info_head), hierarchy);
                }();

                if (creating_new_replica) {
                    const int l1descInx = create_new_replica(*rsComm, *dataObjInp, info_head);

                    if (lockFd > 0) {
                        if (l1descInx < 3) {
                            unlock_data_obj();
                        }
                        else {
                            L1desc[l1descInx].lockFd = lockFd;
                        }
                    }

                    return l1descInx;
                }

                // This is an overwrite - swizzle some flags
                dataObjInp->openFlags |= O_RDWR;
                cond_input[DEST_RESC_NAME_KW] = irods::hierarchy_parser{hierarchy.data()}.first_resc();
                cond_input[OPEN_TYPE_KW] = std::to_string(OPEN_FOR_WRITE_TYPE);
            }

            // The data object information pointer must be populated in order to do anything below.
            if (!info_head) {
                THROW(SYS_REPLICA_DOES_NOT_EXIST, fmt::format(
                    "[{}] - no data object was found for [{}]",
                    __FUNCTION__, dataObjInp->objPath));
            }

            // We need to migrate bundled data to the cache directory before opening. Bundled data is not
            // considered for intermediate replicas as it is legacy behavior, so we simply stage the data
            // and open the replica in this case.
            if (leaf_resource_is_bundleresc(hierarchy)) {
                if (const int ec = stage_bundled_data_to_cache_directory(rsComm, &info_head); ec < 0) {
                    if (lockFd > 0) {
                        unlock_data_obj();
                    }
                    freeAllDataObjInfo(info_head);
                    return ec;
                }

                if (const int ec = apply_static_pep_data_obj_open_pre(*rsComm, *dataObjInp, &info_head); ec < 0) {
                    THROW(ec, "failed in static pre-PEP for rsDataObjOpen");
                }

                auto replica = ir::make_replica_proxy(*info_head);

                const int l1descInx = open_replica(*rsComm, *dataObjInp, replica);
                if (l1descInx < 0) {
                    THROW(l1descInx, fmt::format(
                        "[{}] - failed to open replica:[{}]",
                        __FUNCTION__, l1descInx));
                }
                else if (l1descInx < 3) {
                    THROW(SYS_FILE_DESC_OUT_OF_RANGE, fmt::format(
                        "[{}] - file descriptor out of range:[{}]",
                        __FUNCTION__, l1descInx));
                }

                if ( lockFd >= 0 ) {
                    L1desc[l1descInx].lockFd = lockFd;
                }

                return l1descInx;
            }

            if (info_head->specColl) {
                if (const int ec = apply_static_pep_data_obj_open_pre(*rsComm, *dataObjInp, &info_head); ec < 0) {
                    THROW(ec, "failed in static pre-PEP for rsDataObjOpen");
                }

                auto replica = ir::make_replica_proxy(*info_head);

                const int l1descInx = open_replica(*rsComm, *dataObjInp, replica);
                if (l1descInx < 0) {
                    THROW(l1descInx, fmt::format(
                        "[{}] - failed to open replica:[{}]",
                        __FUNCTION__, l1descInx));
                }
                else if (l1descInx < 3) {
                    THROW(SYS_FILE_DESC_OUT_OF_RANGE, fmt::format(
                        "[{}] - file descriptor out of range:[{}]",
                        __FUNCTION__, l1descInx));
                }

                if ( lockFd >= 0 ) {
                    L1desc[l1descInx].lockFd = lockFd;
                }

                return l1descInx;
            }

            // If the winning replica is not found in the list of replicas, something has gone horribly
            // wrong and we should bail immediately. We need to reference the winning replica whereas in
            // the past the linked list was sorted with the winning replica at the head.
            auto obj = id::make_data_object_proxy(*info_head);

            auto maybe_replica = id::find_replica(obj, hierarchy);
            if (!maybe_replica) {
                THROW(SYS_REPLICA_DOES_NOT_EXIST, fmt::format(
                    "[{}] - no replica found for [{}] on [{}]",
                    __FUNCTION__, obj.logical_path(), hierarchy));
            }

            auto replica = *maybe_replica;

            throw_if_data_object_is_locked(*dataObjInp, replica);

            // Insert the data object information into the replica state table before the replica status is
            // updated because the "before" state is supposed to represent the state of the data object before
            // it is modified (in this particular case, before its replica status is modified).
            rst::insert(obj);

            if (const auto open_for_write = getWriteFlag(dataObjInp->openFlags); open_for_write) {
                if (const int ec = ill::lock_and_publish(*rsComm, replica.data_id(), replica.replica_number(), ill::lock_type::write); ec < 0) {
                    const irods::at_scope_exit erase_rst_entry{[&replica] { rst::erase(replica.data_id()); }};

                    irods::log(LOG_ERROR, fmt::format("failed to lock data object"));

                    rst::update(replica.data_id(), replica.replica_number(),
                        {{"data_is_dirty", rst::get_property(replica.data_id(), replica.replica_number(), "data_is_dirty")}});

                    if (const int ec = ill::unlock_and_publish(*rsComm, replica.data_id(), replica.replica_number(), ill::restore_status); ec < 0) {
                        irods::log(LOG_ERROR, fmt::format(
                            "Failed to unlock data object "
                            "[error_code={}, path={}, hierarchy={}]",
                            ec, dataObjInp->objPath, hierarchy));

                        return ec;
                    }

                    return ec;
                }
            }

            if (const auto ec = apply_static_pep_data_obj_open_pre(*rsComm, *dataObjInp, &info_head); ec < 0) {
                THROW(ec, "failed in static pre-PEP for rsDataObjOpen");
            }

            irods::log(LOG_DEBUG, fmt::format(
                "[{}:{}] - attempting open for [{}], repl:[{}], hier:[{}]",
                __FUNCTION__, __LINE__,
                replica.logical_path(),
                replica.replica_number(),
                replica.hierarchy()));

            const int l1descInx = open_replica(*rsComm, *dataObjInp, replica);
            if (l1descInx < 0) {
                THROW(l1descInx, fmt::format(
                    "[{}] - failed to open replica:[{}]",
                    __FUNCTION__, l1descInx));
            }
            else if (l1descInx < 3) {
                THROW(SYS_FILE_DESC_OUT_OF_RANGE, fmt::format(
                    "[{}] - file descriptor out of range:[{}]",
                    __FUNCTION__, l1descInx));
            }

            try {
                if (INTERMEDIATE_REPLICA == replica.replica_status()) {
                    // Replica tokens only apply to write operations against intermediate replicas.
                    //
                    // There is a case where the client wants to open an existing replica for writes
                    // but does not have a replica token because the client is the first one to open
                    // the replica. "update" should be used when the replica is in an intermediate state.
                    if (rat::contains(replica.data_id(), replica.replica_number())) {
                        update_replica_access_table(*rsComm, update_operation::update, l1descInx, *dataObjInp);
                    }
                    else {
                        update_replica_access_table(*rsComm, update_operation::create, l1descInx, *dataObjInp);
                    }
                }
            }
            catch (const irods::exception& e) {
                const irods::at_scope_exit erase_rst_entry{[&replica] { rst::erase(replica.data_id()); }};

                irods::log(LOG_ERROR, fmt::format(
                           "Could not update replica access table for data object. "
                           "Unlocking data object. "
                           "[error_code={}, path={}, exception={}]",
                           dataObjInp->objPath, e.code(), e.client_display_what()));

                if (const int ec = ill::unlock_and_publish(*rsComm, replica.data_id(), replica.replica_number(), ill::restore_status); ec < 0) {
                    irods::log(LOG_ERROR, fmt::format(
                        "[{}:{}] - Failed to unlock data object "
                        "[error_code=[{}], path=[{}], hierarchy=[{}]",
                        __FUNCTION__, __LINE__, ec, dataObjInp->objPath, hierarchy));
                    return ec;
                }

                return e.code();
            }

            if ( lockFd >= 0 ) {
                L1desc[l1descInx].lockFd = lockFd;
            }

            return l1descInx;
        }
        catch (const irods::exception& e) {
            // TODO: make sure object is unlocked before returning
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.client_display_what()));
            if (lockFd > 0) {
                unlock_data_obj();
            }
            return e.code();
        }
        catch (const std::exception& e) {
            irods::log(LOG_ERROR, fmt::format("[{}:{}] - [{}]", __FUNCTION__, __LINE__, e.what()));
            if (lockFd > 0) {
                unlock_data_obj();
            }
            return SYS_LIBRARY_ERROR;
        }
        catch (...) {
            irods::log(LOG_ERROR, fmt::format("[{}] - unknown error has occurred.", __FUNCTION__));
            if (lockFd > 0) {
                unlock_data_obj();
            }
            return SYS_UNKNOWN_ERROR;
        }
    } // rsDataObjOpen_impl
} // anonymous namespace

int rsDataObjOpen(rsComm_t *rsComm, dataObjInp_t *dataObjInp)
{
    namespace fs = irods::experimental::filesystem;

    if (!dataObjInp) {
        return SYS_INTERNAL_NULL_INPUT_ERR;
    }

    if (has_trailing_path_separator(dataObjInp->objPath)) {
        return USER_INPUT_PATH_ERR;
    }

    if ((dataObjInp->openFlags & O_ACCMODE) == O_RDONLY && (dataObjInp->openFlags & O_TRUNC)) {
        return USER_INCOMPATIBLE_OPEN_FLAGS;
    }

    const auto data_object_exists = fs::server::exists(*rsComm, dataObjInp->objPath);
    const auto fd = rsDataObjOpen_impl(rsComm, dataObjInp);

    constexpr auto minimum_valid_file_descriptor = 3;

    // Update the parent collection's mtime.
    if (fd >= minimum_valid_file_descriptor && !data_object_exists) {
        const auto parent_path = fs::path{dataObjInp->objPath}.parent_path();

        if (fs::server::is_collection_registered(*rsComm, parent_path)) {
            using std::chrono::system_clock;
            using std::chrono::time_point_cast;

            const auto mtime = time_point_cast<fs::object_time_type::duration>(system_clock::now());

            try {
                irods::experimental::scoped_privileged_client spc{*rsComm};
                fs::server::last_write_time(*rsComm, parent_path, mtime);
            }
            catch (const fs::filesystem_error& e) {
                log::api::error(e.what());
                return e.code().value();
            }
        }
    }

    return fd;
}

