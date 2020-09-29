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
    using data_object_proxy = data_object::data_object_proxy<dataObjInfo_t>;
    using replica_proxy     = replica::replica_proxy<dataObjInfo_t>;
} // anonymous namespace

namespace irods::experimental
{
    auto lock_data_object(RsComm& _comm, data_object_proxy& _obj, replica_proxy& _opened_replica, const repl_status_t _lock_type) -> json
    {
        // Set each replica status to the new lock state
        json input;
        input["data_id"] = std::to_string(_obj.data_id());

        for (auto& repl : _obj.replicas()) {
            const json before = replica::to_json(repl);

            if (WRITE_LOCK == _lock_type && _opened_replica.replica_number() == repl.replica_number()) {
                repl.replica_status(INTERMEDIATE_REPLICA);
            }
            else {
                repl.replica_status(_lock_type);
            }

            const json after = replica::to_json(repl);

            input["replicas"].push_back(json{
                {"before", before},
                {"after", after}
            });
        }

        irods::log(LOG_NOTICE, fmt::format("[{}:{}] - input:[{}]", __FUNCTION__, __LINE__, input.dump()));

        // Set catalog information with json structured replica information
        char* output{};
        if (const auto ec = rs_data_object_finalize(&_comm, input.dump().c_str(), &output); ec) {
            log::api::error("[{}] - updating data object failed with [{}]", __FUNCTION__, ec);
            THROW(ec, "error locking data object");
        }

        return input;
    } // lock_data_object
} // namespace irods::experimental
