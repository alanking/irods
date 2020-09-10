#include "irods_logger.hpp"
#include "logical_locking.hpp"
#include "rs_finalize_data_object.hpp"

#include <algorithm>
#include <vector>

namespace {

    using log  = irods::experimental::log;
    using json = nlohmann::json;

    json set_data_object_states(
        rsComm_t& _comm,
        const irods::file_object_ptr _obj,
        const std::vector<repl_status_t>& _status)
    {
        if (_status.size() != _obj->replicas().size()) {
            THROW(SYS_INVALID_INPUT_PARAM, fmt::format(
                "status vector size [{}] does not match replica list size [{}]",
                _status.size(), _obj->replicas().size()));
        }

        // construct json object
        json input;

        // add data_id
        input["data_id"] = std::to_string(_obj->data_id());

        for (auto&& r : _obj->replicas()) {
            // loop over replicas and add information to "before"
            json before = r.to_json();

            // take a modified form of the replica
            irods::physical_object modified_r = r;
            //modified_r.replica_status(static_cast<int>(_lock_type));
            modified_r.replica_status(static_cast<int>(_status.at(modified_r.repl_num())));

            // add modified information to "after"
            json after = modified_r.to_json();

            log::api::info("[{}:{}] - before:[{}],after:[{}]",
                __FUNCTION__, __LINE__, before.dump(), after.dump());

            // push back the "before" and "after" on the replicas json::array
            input["replicas"].push_back(
            {
                {"before", before},
                {"after", after}
            });
        }

        log::api::info("[{}:{}] - json input:[{}]", __FUNCTION__, __LINE__, input.dump());

        // call rs_finalize_data_object
        char* output{};
        if (const auto ec = rs_finalize_data_object(&_comm, input.dump().c_str(), &output); ec) {
            log::api::error("[{}] - updating data object failed with [{}]", __FUNCTION__, ec);
            THROW(ec, "error locking data object");
        }

        // TODO: need to pass back the "before" information to the caller
        // return before and after to retain replica status information...
        return input;

    } // set_data_object_states

} // anonymous namespace

namespace irods::experimental {

    json lock_data_object(
        rsComm_t& _comm,
        const irods::file_object_ptr _obj,
        const repl_status_t _lock_type)
    {
        std::vector<repl_status_t> states;

        //states.reserve(_obj->replicas().size());
        //std::fill(states.begin(), states.end(), _lock_type);
        for (std::size_t i = 0; i < _obj->replicas().size(); ++i) {
            states.push_back(_lock_type);
        }

        return set_data_object_states(_comm, _obj, states);
    } // lock_data_object

    json sync_replica_states_with_catalog(
        rsComm_t& _comm,
        const irods::file_object_ptr _obj)
    {
        std::vector<repl_status_t> states;

        for (auto&& r : _obj->replicas()) {
            states.push_back(static_cast<repl_status_t>(r.replica_status()));
        }

        return set_data_object_states(_comm, _obj, states);
    } // lock_data_object

} // namespace irods::experimental
