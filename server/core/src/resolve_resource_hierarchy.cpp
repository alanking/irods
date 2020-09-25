#include "collection.hpp"
#include "dataObjCreate.h"
#include "dataObjOpr.hpp"
#include "getRescQuota.h"
#include "miscServerFunct.hpp"
#include "objInfo.h"
#include "rsGetRescQuota.hpp"
#include "specColl.hpp"

#include "irods_at_scope_exit.hpp"
#include "irods_hierarchy_parser.hpp"
#include "irods_logger.hpp"
#include "irods_resource_backport.hpp"
#include "irods_resource_redirect.hpp"
#include "key_value_proxy.hpp"
#include "resolve_resource_hierarchy.hpp"
#include "voting.hpp"

#include <algorithm>
#include <string_view>

namespace
{
    // clang-format off
    namespace replica       = irods::experimental::replica;
    namespace data_object   = irods::experimental::data_object;
    using log               = irods::experimental::log;
    using key_value_proxy   = irods::experimental::key_value_proxy<keyValPair_t>;
    using replica_proxy     = irods::experimental::replica::replica_proxy<dataObjInfo_t>;
    using data_object_proxy = irods::experimental::data_object::data_object_proxy<dataObjInfo_t>;
    // clang-format on

    auto throw_if_operation_is_not_supported(std::string_view _operation) -> void
    {
        const std::vector<std::string_view> supported_operations{
            irods::CREATE_OPERATION,
            irods::OPEN_OPERATION,
            irods::WRITE_OPERATION,
            irods::UNLINK_OPERATION};

        const bool operation_supported = std::any_of(
            std::begin(supported_operations), std::end(supported_operations),
            [&_operation](std::string_view _o) { return _operation == _o; }
        );

        if (!operation_supported) {
            THROW(SYS_NOT_SUPPORTED, fmt::format("operation not supported [{}]", _operation));
        }
    } // throw_if_operation_is_not_supported

    std::string_view get_keyword_from_inp(const key_value_proxy& _cond_input)
    {
        std::string_view key_word;
        if (_cond_input.contains(RESC_NAME_KW)) {
            key_word = _cond_input.at(RESC_NAME_KW).value();
        }
        if (_cond_input.contains(DEST_RESC_NAME_KW)) {
            key_word = _cond_input.at(DEST_RESC_NAME_KW).value();
        }
        if (_cond_input.contains(BACKUP_RESC_NAME_KW)) {
            key_word = _cond_input.at(BACKUP_RESC_NAME_KW).value();
        }
        if (!key_word.empty()) {
            irods::resource_ptr resc;
            irods::error ret = resc_mgr.resolve( key_word.data(), resc );
            if ( !ret.ok() ) {
                THROW(ret.code(), ret.result());
            }
            irods::resource_ptr parent;
            ret = resc->get_parent(parent);
            if (ret.ok()) {
                THROW(DIRECT_CHILD_ACCESS, "key_word contains child resource");
            }
        }
        return key_word;
    } // get_keyword_from_inp

    auto apply_policy_for_create_operation(RsComm& _comm, dataObjInp_t& _inp) -> std::string
    {
        // get resource name
        ruleExecInfo_t rei{};
        irods::at_scope_exit free_rei_data{[&]
        {
            clearKeyVal(rei.condInputData);
            free(rei.condInputData);
        }};

        initReiWithDataObjInp( &rei, &_comm, &_inp );

        std::string_view rule_name = REPLICATE_OPR == _inp.oprType ? "acSetRescSchemeForRepl"
                                                                   : "acSetRescSchemeForCreate";

        if (int ec = applyRule(rule_name.data(), NULL, &rei, NO_SAVE_REI); ec < 0) {
            if (rei.status < 0) {
                ec = rei.status;
            }

            THROW(ec, fmt::format(
                "[{}]:acSetRescSchemeForCreate error for {},status={}",
                __FUNCTION__, _inp.objPath, ec));
        }

        std::string resc_name;
        if (!strlen(rei.rescName)) {
            auto set_err = irods::set_default_resource(&_comm, "", "", &_inp.condInput, resc_name);
            if (!set_err.ok()) {
                THROW(SYS_INVALID_RESC_INPUT, set_err.result());
            }
        }
        else {
            resc_name = rei.rescName;
        }

        // set resource quota
        const int ec = setRescQuota(&_comm, _inp.objPath, resc_name.c_str(), _inp.dataSize);
        if(SYS_RESC_QUOTA_EXCEEDED == ec) {
            THROW(SYS_RESC_QUOTA_EXCEEDED, "resource quota exceeded");
        }

        return resc_name;
    } // apply_policy_for_create_operation

    // function to handle collecting a vote from a resource for a given operation and fco
    auto request_vote_for_data_object(
        RsComm&           _comm,
        std::string_view  _operation,
        std::string_view  _resource_name,
        data_object_proxy _obj) -> data_object::vote_type
    {
        namespace irv = irods::experimental::resource::voting;

        irods::resource_ptr resource = resc_mgr.resolve(_resource_name.data());

        if (resource->has_parent()) {
            THROW(DIRECT_CHILD_ACCESS, "attempt to directly address a child resource");
        }

        std::string_view host_name = _comm.myEnv.rodsHost;

        irods::hierarchy_parser parser;
        float vote{};

        // TODO: remove use of file_object_ptr in voting interface
        irods::file_object_ptr file_obj = irods::to_file_object(_comm, *_obj.get(), _obj.requested_replica());

        auto fco = boost::dynamic_pointer_cast<irods::first_class_object>(file_obj);

        auto err = resource->call<const std::string&, const std::string&, irods::hierarchy_parser&, float&>(
            &_comm, irods::RESOURCE_OP_RESOLVE_RESC_HIER, fco, _operation.data(), host_name.data(), parser, vote);

        const std::string hier = parser.str();

        irods::log(LOG_NOTICE, fmt::format(
            "[{}:{}] - resolved hier for obj [{}] with vote:[{}],hier:[{}],err.code:[{}]",
            __FUNCTION__, __LINE__, file_obj->logical_path(), vote, hier, err.code()));

        if (!err.ok() || irv::vote::zero == vote) {
            THROW(HIERARCHY_ERROR,
                fmt::format("failed in call to {} host [{}] hier [{}] vote [{}]",
                irods::RESOURCE_OP_RESOLVE_RESC_HIER, host_name, hier, vote));
        }

        return {hier, vote};
    } // request_vote_for_data_object

    auto resolve_hierarchy_for_existing_replica(
        RsComm&            _comm,
        data_object_proxy& _obj,
        std::string_view   _key_word,
        std::string_view   _operation) -> data_object::vote_type
    {
        namespace irv = irods::experimental::resource::voting;

        std::vector<std::string> root_resources;
        for (const auto& repl : _obj.replicas()) {
            root_resources.push_back(irods::hierarchy_parser{repl.hierarchy().data()}.first_resc());
        }

        if (root_resources.empty()) {
            THROW(SYS_REPLICA_DOES_NOT_EXIST, "file object has no replicas");
        }

        std::string max_hier = "";
        float max_vote = -1.0;

        bool kw_match_found = false;

        for (const auto& resource : root_resources) {
            irods::log(LOG_NOTICE, fmt::format(
                "[{}:{}] - requesting vote from root [{}] for [{}]",
                __FUNCTION__, __LINE__, resource, _obj.logical_path()));

            try {
                const auto [hier, vote] = request_vote_for_data_object(_comm, _operation, resource, _obj);

                irods::log(LOG_NOTICE, fmt::format(
                    "[{}:{}] - root:[{}],max_hier:[{}],max_vote:[{}],vote:[{}],hier:[{}]",
                    __FUNCTION__, __LINE__, resource, max_hier, max_vote, vote, hier));

                if (vote > max_vote) {
                    max_vote = vote;
                    max_hier = hier;
                }

                if (irv::vote::zero != vote && !kw_match_found && !_key_word.empty() && resource == _key_word) {
                    irods::log(LOG_NOTICE, fmt::format(
                        "[{}:{}] - with keyword... kw:[{}],root:[{}],max_hier:[{}],max_vote:[{}],vote:[{}],hier:[{}]",
                        __FUNCTION__, __LINE__, _key_word, resource, max_hier, max_vote, vote, hier));

                    kw_match_found = true;
                    _obj.winner({hier, vote});

                    irods::log(LOG_NOTICE, fmt::format("[{}:{}] - winner:[{}],vote:[{}]",
                        __FUNCTION__, __LINE__, hier, vote));
                }
            }
            catch (const irods::exception& e) {
                irods::log(LOG_NOTICE, fmt::format("[{}:{}] - vote failed for [{}] on [{}] with [{}]",
                        __FUNCTION__, __LINE__, _obj.logical_path(), resource, e.what()));
            }
        }

        const double diff = max_vote - 0.00000001;
        if (diff <= irv::vote::zero) {
            THROW(HIERARCHY_ERROR, "no valid resource found for data object");
        }

        // set the max vote as the winner if a keyword was not being considered
        if (!kw_match_found) {
            irods::log(LOG_NOTICE, fmt::format("[{}:{}] - winner:[{}],vote:[{}]", __FUNCTION__, __LINE__, max_hier, max_vote));
            _obj.winner({max_hier, max_vote});
        }

        return _obj.winner();
    } // resolve_hierarchy_for_existing_replica

    // function to handle resolving the hier given the fco and resource keyword
    auto resolve_hierarchy_for_create(
        RsComm&            _comm,
        data_object_proxy& _obj,
        std::string_view   _key_word) -> data_object::vote_type
    {
        namespace irv = irods::experimental::resource::voting;

        const auto [hier, vote] = request_vote_for_data_object(_comm, irods::CREATE_OPERATION, _key_word, _obj);

        if (irv::vote::zero == vote) {
            THROW(HIERARCHY_ERROR, "vote failed - highest vote was 0.0");
        }

        log::server::debug("[{}:{}] - winner:[{}],vote:[{}]",
            __FUNCTION__, __LINE__, hier, vote);

        _obj.winner({hier, vote});

        return _obj.winner();
    } // resolve_hierarchy_for_create
} // anonymous namespace

namespace irods::experimental::resource
{
    auto resolve_resource_hierarchy(
        RsComm&             _comm,
        std::string_view    _operation,
        dataObjInp_t& _inp) -> data_object::vote_type
    {
        auto [obj, lm] = data_object::make_data_object_proxy(_comm, _inp.objPath);
        lm.release(); // intentionally wresting control of the underlying memory
        return resolve_resource_hierarchy(_comm, _operation, _inp, obj);
    } // resolve_resource_hierarchy

    auto resolve_resource_hierarchy(
        RsComm&             _comm,
        std::string_view    _operation,
        dataObjInp_t&       _inp,
        data_object_proxy&  _obj) -> data_object::vote_type
    {
        throw_if_operation_is_not_supported(_operation);

        // if this is a special collection then we need to get the hier
        // pass that along and bail as it is not a data object, or if
        // it is just a not-so-special collection then we continue with
        // processing the operation, as this may be a create op
        rodsObjStat_t *rodsObjStatOut = NULL;
        if (collStat(&_comm, &_inp, &rodsObjStatOut) >= 0 && rodsObjStatOut->specColl) {
            std::string hier = rodsObjStatOut->specColl->rescHier;
            freeRodsObjStat( rodsObjStatOut );

            _obj.winner({hier, 1.0f});

            return _obj.winner();
        }
        freeRodsObjStat(rodsObjStatOut);

        const auto cond_input = irods::experimental::make_key_value_proxy(_inp.condInput);
        std::string_view key_word = get_keyword_from_inp(cond_input);

        // Providing a replica number means the client is attempting to target an existing replica.
        // Therefore, usage of the replica number cannot be used during a create operation. The
        // operation must be changed so that the system does not attempt to create the replica.
        std::string actual_op = _operation.data();
        if (irods::CREATE_OPERATION == _operation && cond_input.contains(REPL_NUM_KW)) {
            actual_op = irods::WRITE_OPERATION;
        }

        const char* default_resc_name = nullptr;
        if (cond_input.contains(DEF_RESC_NAME_KW)) {
            default_resc_name = cond_input.at(DEF_RESC_NAME_KW).value().data();
        }

        if (irods::CREATE_OPERATION == actual_op) {
            std::string create_resc_name = !key_word.empty() ? key_word.data()
                                         : default_resc_name ? default_resc_name
                                         : "";

            create_resc_name = apply_policy_for_create_operation(_comm, _inp);

            // TODO: Can we do a vote for a create first?
            if (_obj.in_catalog() && data_object::hierarchy_has_replica(create_resc_name, *_obj.get())) {
                actual_op = irods::WRITE_OPERATION;
            }
            else {
                return resolve_hierarchy_for_create(_comm, _obj, create_resc_name);
            }
        }

        if (!_obj.in_catalog()) {
            THROW(HIERARCHY_ERROR, "data object does not exist");
        }

        // consider force flag - we need to consider the default resc if -f is specified
        if (cond_input.contains(FORCE_FLAG_KW) && default_resc_name && key_word.empty()) {
            key_word = default_resc_name;
        }

        return resolve_hierarchy_for_existing_replica(_comm, _obj, key_word, actual_op);
    } // resolve_resource_hierarchy
} // namespace irods::experimental::resource
