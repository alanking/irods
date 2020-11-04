#include "dataObjOpr.hpp"
#include "dataObjTrim.h"
#include "dataObjUnlink.h"
#include "getRemoteZoneResc.h"
#include "icatDefines.h"
#include "objMetaOpr.hpp"
#include "rodsLog.h"
#include "rsDataObjOpen.hpp"
#include "rsDataObjTrim.hpp"
#include "rsDataObjUnlink.hpp"
#include "specColl.hpp"

#include "irods_resource_redirect.hpp"
#include "irods_hierarchy_parser.hpp"
#include "irods_at_scope_exit.hpp"
#include "irods_linked_list_iterator.hpp"

#define IRODS_REPLICA_ENABLE_SERVER_SIDE_API
#include "data_object_proxy.hpp"

#include <tuple>

namespace
{
    // clang-format off
    using c_data_object_proxy = irods::experimental::data_object::data_object_proxy<const DataObjInfo>;
    using c_replica_proxy     = irods::experimental::replica::replica_proxy<const DataObjInfo>;
    using trim_list_type      = std::vector<const DataObjInfo*>;
    // clang-format on

    int get_time_of_expiration(const char* age_kw) {
        if (!age_kw) {
            return 0;
        }
        try {
            const auto age_in_minutes = std::atoi(age_kw);
            if ( age_in_minutes > 0 ) {
                const auto now = time(0);
                const auto age_in_seconds = age_in_minutes * 60;
                return now - age_in_seconds;
            }
            return 0;
        }
        catch (const std::exception&) {
            return 0;
        }
    }

    unsigned long get_minimum_replica_count(const char* copies_kw) {
        if (!copies_kw) {
            return DEF_MIN_COPY_CNT;
        }
        try {
            const auto minimum_replica_count = std::stoul(copies_kw);
            if (0 == minimum_replica_count) {
                return DEF_MIN_COPY_CNT;
            }
            return minimum_replica_count;
        }
        catch (const std::invalid_argument&) {
            return DEF_MIN_COPY_CNT;
        }
        catch (const std::out_of_range&) {
            return DEF_MIN_COPY_CNT;
        }
    }

    auto resolve_resource_hierarchy_for_trim(RsComm& _comm, DataObjInp& _inp) -> DataObjInfo*
    {
        DataObjInfo* info_head{};

        if (!getValByKey(&_inp.condInput, RESC_HIER_STR_KW)) {
            irods::resolve_resource_hierarchy(irods::UNLINK_OPERATION, &_comm, _inp, &info_head);
        }
        else {
            irods::file_object_ptr tmp{new irods::file_object()};
            if (const auto err = irods::file_object_factory(&_comm, &_inp, tmp, &info_head); !err.ok()) {
                THROW(err.code(), "file_object_factory failed");
            }
        }

        if (!info_head) {
            THROW(SYS_REPLICA_DOES_NOT_EXIST, fmt::format(
                "[{}] - no results for [{}] returned from resolve_resource_hierarchy",
                __FUNCTION__, _inp.objPath));
        }

        return info_head;
    } // resolve_resource_hierarchy_for_trim

    auto get_list_of_replicas_to_trim(DataObjInp& _inp, const c_data_object_proxy& _obj) -> trim_list_type
    {
        auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);

        trim_list_type trim_list;

        const unsigned long good_replica_count = std::count_if(
            std::begin(_obj.replicas()), std::end(_obj.replicas()),
            [](const auto& _replica) {
                return GOOD_REPLICA == _replica.replica_status();
            });

        const auto minimum_replica_count = get_minimum_replica_count(getValByKey(&_inp.condInput, COPIES_KW));
        const auto expiration = get_time_of_expiration(getValByKey(&_inp.condInput, AGE_KW));
        const auto expired = [&expiration](const c_replica_proxy& _replica) {
            return expiration && std::stoi(_replica.mtime().data()) > expiration;
        };

        // If a specific replica number is specified, only trim that one!
        if (cond_input.contains(REPL_NUM_KW)) {
            try {
                const auto repl_num = std::stoi(cond_input.at(REPL_NUM_KW).value().data());

                const auto repl = std::find_if(
                    std::cbegin(_obj.replicas()), std::cend(_obj.replicas()),
                    [&repl_num](const auto& _replica) {
                        return repl_num == _replica.replica_number();
                    });

                if (repl == std::cend(_obj.replicas())) {
                    THROW(SYS_REPLICA_DOES_NOT_EXIST, "target replica does not exist");
                }

                if (expired(*repl)) {
                    THROW(USER_INCOMPATIBLE_PARAMS, "target replica is not old enough for removal");
                }

                if (good_replica_count <= minimum_replica_count && GOOD_REPLICA == repl->replica_status()) {
                    THROW(USER_INCOMPATIBLE_PARAMS, "cannot remove the last good replica");
                }

                trim_list.push_back(repl->get());

                return trim_list;
            }
            catch (const std::invalid_argument& e) {
                irods::log(LOG_ERROR, e.what());
                THROW(USER_INVALID_REPLICA_INPUT, "invalid replica number requested");
            }
            catch (const std::out_of_range& e) {
                irods::log(LOG_ERROR, e.what());
                THROW(USER_INVALID_REPLICA_INPUT, "invalid replica number requested");
            }
        }

        std::string_view resc_name;
        if (cond_input.contains(RESC_NAME_KW)) {
            resc_name = cond_input.at(RESC_NAME_KW).value().data();
        }

        const auto matches_target_resource = [&resc_name](const c_replica_proxy& _replica) {
            return resc_name == irods::hierarchy_parser{_replica.hierarchy().data()}.first_resc();
        };

        // Walk list and add stale replicas to the list
        for (const auto& replica : _obj.replicas()) {
            if (STALE_REPLICA == replica.replica_status()) {
                if (expired(replica) || !matches_target_resource(replica)) {
                    continue;
                }
                trim_list.push_back(replica.get());
            }
        }

        if (good_replica_count <= minimum_replica_count) {
            return trim_list;
        }

        // If we have not reached the minimum count, walk list again and add good replicas
        unsigned long good_replicas_to_be_trimmed = 0;
        for (const auto& replica : _obj.replicas()) {
            if (GOOD_REPLICA == replica.replica_status()) {
                if (expired(replica) || !matches_target_resource(replica)) {
                    continue;
                }

                if (good_replica_count - good_replicas_to_be_trimmed <= minimum_replica_count) {
                    return trim_list;
                }

                trim_list.push_back(replica.get());

                good_replicas_to_be_trimmed++;
            }
        }

        return trim_list;
    } // get_list_of_replicas_to_trim
} // anonymous namespace

int rsDataObjTrim(rsComm_t *rsComm, dataObjInp_t *dataObjInp)
{
    if (!dataObjInp) {
        return SYS_INTERNAL_NULL_INPUT_ERR;
    }

    auto cond_input = irods::experimental::make_key_value_proxy(dataObjInp->condInput);

    // -S and -n are incompatible...
    if (cond_input.contains(RESC_NAME_KW) && cond_input.contains(REPL_NUM_KW)) {
        return USER_INCOMPATIBLE_PARAMS;
    }
    // TODO: If !repl_num && !resc_name, use default resource.

    rodsServerHost_t *rodsServerHost;
    specCollCache_t *specCollCache{};

    resolveLinkedPath( rsComm, dataObjInp->objPath, &specCollCache, &dataObjInp->condInput );
    int remoteFlag = getAndConnRemoteZone( rsComm, dataObjInp, &rodsServerHost, REMOTE_OPEN );

    if ( remoteFlag < 0 ) {
        return remoteFlag;
    }
    else if ( remoteFlag == REMOTE_HOST ) {
        return rcDataObjTrim( rodsServerHost->conn, dataObjInp );
    }

    int retVal = 0;
    try {
        namespace data_object = irods::experimental::data_object;

        // Temporarily remove REPL_NUM_KW to ensure we are returned all replicas in the list
        std::string repl_num;
        if (cond_input.contains(REPL_NUM_KW)) {
            repl_num = cond_input.at(REPL_NUM_KW).value().data();
            cond_input.erase(REPL_NUM_KW);
        }

        const auto* info_head = resolve_resource_hierarchy_for_trim(*rsComm, *dataObjInp);
        const auto obj = data_object::make_data_object_proxy(*info_head);
        const auto obj_lm = irods::experimental::lifetime_manager{*obj.get()};

        if (!repl_num.empty()) {
            cond_input[REPL_NUM_KW] = repl_num;
        }

        for (const auto* replica : get_list_of_replicas_to_trim(*dataObjInp, obj)) {
            if (cond_input.contains(DRYRUN_KW)) {
                retVal = 1;
                continue;
            }

            auto [r, r_lm] = irods::experimental::replica::duplicate_replica(*replica);

            if (const int ec = dataObjUnlinkS(rsComm, dataObjInp, r.get()); ec < 0) {
                retVal = (0 == retVal) ? ec : retVal;
            }
            else {
                retVal = 1;
            }
        }
    }
    catch (const irods::exception& e) {
        irods::log(LOG_NOTICE, e.what());
        return e.code();
    }
    catch (const std::invalid_argument& e) {
        irods::log(LOG_ERROR, e.what());
        return USER_INCOMPATIBLE_PARAMS;
    }
    catch (const std::exception& e) {
        irods::log(LOG_ERROR, e.what());
        return SYS_LIBRARY_ERROR;
    }
    catch (...) {
        irods::log(LOG_ERROR, fmt::format("[{}] - unknown error occurred during trim", __FUNCTION__));
        return SYS_UNKNOWN_ERROR;
    }

    return retVal;
} // rsDataObjTrim
