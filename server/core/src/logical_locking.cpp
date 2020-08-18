#include "irods_logger.hpp"
#include "logical_locking.hpp"
#include "rs_data_object_finalize.hpp"

#include <algorithm>
#include <vector>

namespace
{
    namespace replica       = irods::experimental::replica;
    namespace data_object   = irods::experimental::data_object;
    using log               = irods::experimental::log;
    using json              = nlohmann::json;
    using data_object_proxy = data_object::data_object_proxy<const dataObjInfo_t>;
    using replica_proxy     = replica::replica_proxy<const dataObjInfo_t>;
} // anonymous namespace

namespace irods::experimental
{
    auto lock_data_object(
        RsComm& _comm,
        const dataObjInfo_t& _info,
        const repl_status_t _lock_type) -> json
    {
        const auto _obj = data_object_proxy{_info};

        auto input = data_object::to_json(_obj);

        // Set each replica status to the new lock state
        for (auto&& replica : input["replicas"]) {
            auto& after = replica["after"];
            after["data_is_dirty"] = std::to_string(_lock_type);
        }

        // TODO: update the actual structure?

        // Set catalog information with json structured replica information
        char* output{};
        if (const auto ec = rs_data_object_finalize(&_comm, input.dump().c_str(), &output); ec) {
            log::api::error("[{}] - updating data object failed with [{}]", __FUNCTION__, ec);
            THROW(ec, "error locking data object");
        }

        return input;
    } // lock_data_object
} // namespace irods::experimental
