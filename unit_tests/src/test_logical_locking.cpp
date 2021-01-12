#include "catch.hpp"

#include "client_connection.hpp"
#include "dataObjInpOut.h"
#include "dstream.hpp"
#include "filesystem.hpp"
#include "irods_at_scope_exit.hpp"
#include "irods_error_enum_matcher.hpp"
#include "irods_exception.hpp"
#include "replica.hpp"
#include "replica_proxy.hpp"
#include "resource_administration.hpp"
#include "rodsClient.h"
#include "rodsErrorTable.h"
#include "transport/default_transport.hpp"
#include "unit_test_utils.hpp"

#include "fmt/format.h"

#include <iostream>
#include <thread>

TEST_CASE("logical_locking", "[logical_locking]")
{
    using namespace std::string_literals;
    using namespace std::chrono_literals;
    namespace adm = irods::experimental::administration;
    namespace fs = irods::experimental::filesystem;
    namespace io = irods::experimental::io;
    namespace replica = irods::experimental::replica;

    load_client_api_plugins();

    // create two resources onto which a data object can be written
    const std::string resc_0 = "get_data_obj_info_resc_0";
    const std::string resc_1 = "get_data_obj_info_resc_1";

    irods::at_scope_exit remove_resources{[&resc_0, &resc_1] {
        // reset connection to ensure resource manager is current
        irods::experimental::client_connection conn;
        RcComm& comm = static_cast<RcComm&>(conn);

        adm::client::remove_resource(comm, resc_0);
        adm::client::remove_resource(comm, resc_1);
    }};

    const auto mkresc = [](std::string_view _name)
    {
        irods::experimental::client_connection conn;
        RcComm& comm = static_cast<RcComm&>(conn);

        if (const auto [ec, exists] = adm::client::resource_exists(comm, _name); exists) {
            REQUIRE(adm::client::remove_resource(comm, _name));
        }

        REQUIRE(unit_test_utils::add_ufs_resource(comm, _name, "vault_for_"s + _name.data()));
    };

    mkresc(resc_0);
    mkresc(resc_1);

    // reset connection so resources exist
    irods::experimental::client_connection conn;
    RcComm& comm = static_cast<RcComm&>(conn);

    // create data object on one resource
    rodsEnv env;
    _getRodsEnv(env);

    const auto sandbox = fs::path{env.rodsHome} / "test_logical_locking";

    if (!fs::client::exists(comm, sandbox)) {
        REQUIRE(fs::client::create_collection(comm, sandbox));
    }

    irods::at_scope_exit remove_sandbox{[&sandbox] {
        irods::experimental::client_connection conn;
        RcComm& comm = static_cast<RcComm&>(conn);

        REQUIRE(fs::client::remove_all(comm, sandbox, fs::remove_options::no_trash));
    }};

    const auto target_object = sandbox / "target_object";

    {
        io::client::default_transport tp{comm};
        io::odstream{tp, target_object, io::root_resource_name{resc_0}};
    }

    REQUIRE(fs::client::exists(comm, target_object));

    REQUIRE(unit_test_utils::replicate_data_object(comm, target_object.c_str(), resc_1));

    SECTION("write lock")
    {
        irods::experimental::client_connection conn;
        RcComm& comm = static_cast<RcComm&>(conn);

        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, 0));
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, 1));

        dataObjInp_t open_inp{};
        std::snprintf(open_inp.objPath, sizeof(open_inp.objPath), "%s", target_object.c_str());
        open_inp.openFlags = O_WRONLY;
        auto cond_input = irods::experimental::make_key_value_proxy(open_inp.condInput);
        cond_input[RESC_HIER_STR_KW] = resc_0;

        const auto fd = rcDataObjOpen(&comm, &open_inp);
        REQUIRE(fd > 2);

        CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
        CHECK(WRITE_LOCKED_REPLICA == replica::replica_status(comm, target_object, 1));

        // Ensure that the lock is effective
        {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            dataObjInp_t open_inp_2{};
            std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", target_object.c_str());
            open_inp_2.openFlags = O_WRONLY;
            auto cond_input = irods::experimental::make_key_value_proxy(open_inp.condInput);

            // Try to open the intermediate replica
            cond_input[REPL_NUM_KW] = std::to_string(0);

            REQUIRE(HIERARCHY_ERROR == rcDataObjOpen(&comm, &open_inp_2));
            CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
            CHECK(WRITE_LOCKED_REPLICA == replica::replica_status(comm, target_object, 1));

            // Try to open the write-locked replica
            cond_input[REPL_NUM_KW] = std::to_string(1);

            REQUIRE(HIERARCHY_ERROR == rcDataObjOpen(&comm, &open_inp_2));
            CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
            CHECK(WRITE_LOCKED_REPLICA == replica::replica_status(comm, target_object, 1));
        }

        openedDataObjInp_t close_inp{};
        close_inp.l1descInx = fd;
        REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, 0));
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, 1));
    }
}
