#include "catch.hpp"

#include "client_connection.hpp"
#include "dataObjChksum.h"
#include "dataObjInpOut.h"
#include "dstream.hpp"
#include "filesystem.hpp"
#include "get_file_descriptor_info.h"
#include "irods_at_scope_exit.hpp"
#include "irods_error_enum_matcher.hpp"
#include "irods_exception.hpp"
#include "replica.hpp"
#include "replica_proxy.hpp"
#include "rodsClient.h"
#include "rodsErrorTable.h"
#include "transport/default_transport.hpp"
#include "unit_test_utils.hpp"

#include "fmt/format.h"

#include <iostream>
#include <thread>

using namespace std::chrono_literals;
namespace fs = irods::experimental::filesystem;
namespace replica = irods::experimental::replica;

static const std::string DEFAULT_RESOURCE_HIERARCHY = "demoResc";

TEST_CASE("open,read,write,close")
{
    try {
        load_client_api_plugins();

        irods::experimental::client_connection setup_conn;
        RcComm& setup_comm = static_cast<RcComm&>(setup_conn);

        rodsEnv env;
        _getRodsEnv(env);

        const auto sandbox = fs::path{env.rodsHome} / "test_rc_data_obj";
        if (!fs::client::exists(setup_comm, sandbox)) {
            REQUIRE(fs::client::create_collection(setup_comm, sandbox));
        }

        irods::at_scope_exit remove_sandbox{[&sandbox] {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            REQUIRE(fs::client::remove_all(comm, sandbox, fs::remove_options::no_trash));
        }};

        const auto target_object = sandbox / "target_object";

        std::string_view path_str = target_object.c_str();

        std::string contents = "content!";

        SECTION("open for write,open for read,close for write,close for read")
        {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            unit_test_utils::create_empty_replica(comm, target_object);

            // open for write
            dataObjInp_t open_inp_1{};
            std::snprintf(open_inp_1.objPath, sizeof(open_inp_1.objPath), "%s", path_str.data());
            open_inp_1.openFlags = O_WRONLY;
            const auto fd_1 = rcDataObjOpen(&comm, &open_inp_1);
            REQUIRE(fd_1 > 2);
            REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));

            // open for read without pre-determeined resource hierarchy (i.e. request vote)
            {
                dataObjInp_t open_inp_2{};
                std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
                open_inp_2.openFlags = O_RDONLY;
                REQUIRE(HIERARCHY_ERROR == rcDataObjOpen(&comm, &open_inp_2));
                REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
            }

            // open for read with pre-determined resource hierarchy
            {
                dataObjInp_t open_inp_2{};
                auto cond_input_2 = irods::experimental::make_key_value_proxy(open_inp_2.condInput);
                cond_input_2[RESC_HIER_STR_KW] = DEFAULT_RESOURCE_HIERARCHY;
                std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
                open_inp_2.openFlags = O_RDONLY;
                REQUIRE(INTERMEDIATE_REPLICA_ACCESS == rcDataObjOpen(&comm, &open_inp_2));
                REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
            }

            // get replica token to properly open the replica
            const nlohmann::json input{{"fd", fd_1}};
            char* json_output{};
            REQUIRE(rc_get_file_descriptor_info(&comm, input.dump().c_str(), &json_output) == 0);
            const auto out = nlohmann::json::parse(json_output);
            const std::string token = out.at("replica_token");

            // use replica access token and pre-determined resource hierarchy
            dataObjInp_t open_inp_2{};
            auto cond_input_2 = irods::experimental::make_key_value_proxy(open_inp_2.condInput);
            cond_input_2[RESC_HIER_STR_KW] = DEFAULT_RESOURCE_HIERARCHY;
            cond_input_2[REPLICA_TOKEN_KW] = token;
            std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
            open_inp_2.openFlags = O_RDONLY;
            const auto fd_2 = rcDataObjOpen(&comm, &open_inp_2);
            REQUIRE(fd_2 > 2);
            REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));

            REQUIRE(fd_2 != fd_1);

            //std::this_thread::sleep_for(2s);

            // close the file descriptor for write
            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_1;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                //CHECK(replica_info.mtime() != replica_info.ctime());
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                CHECK(GOOD_REPLICA == replica_info.replica_status());
            }

            // close the file descriptor for read
            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_2;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                CHECK(GOOD_REPLICA == replica_info.replica_status());
            }
        }

        SECTION("open for write,open for read,close for read,close for write")
        {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            unit_test_utils::create_empty_replica(comm, target_object);

            // open for write
            dataObjInp_t open_inp_1{};
            std::snprintf(open_inp_1.objPath, sizeof(open_inp_1.objPath), "%s", path_str.data());
            open_inp_1.openFlags = O_WRONLY;
            const auto fd_1 = rcDataObjOpen(&comm, &open_inp_1);
            REQUIRE(fd_1 > 2);
            REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));

            // open for read without pre-determeined resource hierarchy (i.e. request vote)
            {
                dataObjInp_t open_inp_2{};
                std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
                open_inp_2.openFlags = O_RDONLY;
                REQUIRE(HIERARCHY_ERROR == rcDataObjOpen(&comm, &open_inp_2));
                REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
            }

            // open for read with pre-determined resource hierarchy
            {
                dataObjInp_t open_inp_2{};
                auto cond_input_2 = irods::experimental::make_key_value_proxy(open_inp_2.condInput);
                cond_input_2[RESC_HIER_STR_KW] = DEFAULT_RESOURCE_HIERARCHY;
                std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
                open_inp_2.openFlags = O_RDONLY;
                REQUIRE(INTERMEDIATE_REPLICA_ACCESS == rcDataObjOpen(&comm, &open_inp_2));
                REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
            }

            // get replica token to properly open the replica
            const nlohmann::json input{{"fd", fd_1}};
            char* json_output{};
            REQUIRE(rc_get_file_descriptor_info(&comm, input.dump().c_str(), &json_output) == 0);
            const auto out = nlohmann::json::parse(json_output);
            const std::string token = out.at("replica_token");

            // use replica access token and pre-determined resource hierarchy
            dataObjInp_t open_inp_2{};
            auto cond_input_2 = irods::experimental::make_key_value_proxy(open_inp_2.condInput);
            cond_input_2[RESC_HIER_STR_KW] = DEFAULT_RESOURCE_HIERARCHY;
            cond_input_2[REPLICA_TOKEN_KW] = token;
            std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
            open_inp_2.openFlags = O_RDONLY;
            const auto fd_2 = rcDataObjOpen(&comm, &open_inp_2);
            REQUIRE(fd_2 > 2);
            REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));

            REQUIRE(fd_2 != fd_1);

            //std::this_thread::sleep_for(2s);

            // close the file descriptor for read
            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_2;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                REQUIRE(INTERMEDIATE_REPLICA == replica_info.replica_status());
            }

            // close the file descriptor for write
            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_1;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                //CHECK(replica_info.mtime() != replica_info.ctime());
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                REQUIRE(GOOD_REPLICA == replica_info.replica_status());
            }
        }

        SECTION("open for read,open for write,close x2")
        {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            unit_test_utils::create_empty_replica(comm, target_object);

            dataObjInp_t open_inp_1{};
            std::snprintf(open_inp_1.objPath, sizeof(open_inp_1.objPath), "%s", path_str.data());
            open_inp_1.openFlags = O_RDONLY;
            const auto fd_1 = rcDataObjOpen(&comm, &open_inp_1);
            REQUIRE(fd_1 > 2);
            REQUIRE(GOOD_REPLICA == replica::replica_status(comm, target_object, 0));

            dataObjInp_t open_inp_2{};
            std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
            open_inp_2.openFlags = O_WRONLY;
            const auto fd_2 = rcDataObjOpen(&comm, &open_inp_2);
            REQUIRE(fd_2 > 2);
            REQUIRE(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));

            REQUIRE(fd_2 != fd_1);

            //std::this_thread::sleep_for(2s);

            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_1;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                //CHECK(replica_info.mtime() == replica_info.ctime());
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                CHECK(INTERMEDIATE_REPLICA == replica_info.replica_status());
            }

            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_2;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                //CHECK(replica_info.mtime() != replica_info.ctime());
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                CHECK(GOOD_REPLICA == replica_info.replica_status());
            }
        }

        SECTION("open for read x2,close x2")
        {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            unit_test_utils::create_empty_replica(comm, target_object);

            dataObjInp_t open_inp_1{};
            std::snprintf(open_inp_1.objPath, sizeof(open_inp_1.objPath), "%s", path_str.data());
            open_inp_1.openFlags = O_RDONLY;
            const auto fd_1 = rcDataObjOpen(&comm, &open_inp_1);
            REQUIRE(fd_1 > 2);
            CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, 0));

            dataObjInp_t open_inp_2{};
            std::snprintf(open_inp_2.objPath, sizeof(open_inp_2.objPath), "%s", path_str.data());
            open_inp_2.openFlags = O_RDONLY;
            const auto fd_2 = rcDataObjOpen(&comm, &open_inp_2);
            REQUIRE(fd_2 > 2);
            CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, 0));

            REQUIRE(fd_2 != fd_1);

            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_1;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                //CHECK(replica_info.mtime() == replica_info.ctime());
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                CHECK(GOOD_REPLICA == replica_info.replica_status());
            }

            {
                openedDataObjInp_t close_inp{};
                close_inp.l1descInx = fd_2;
                REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);

                // ensure all system metadata were restored properly
                const auto [replica_info, replica_lm] = replica::make_replica_proxy(comm, target_object, 0);
                //CHECK(replica_info.mtime() == replica_info.ctime());
                CHECK(0 == static_cast<unsigned long>(replica_info.size()));
                CHECK(GOOD_REPLICA == replica_info.replica_status());
            }
        }
    }
    catch (const irods::exception& e) {
        std::cout << e.client_display_what();
    }
    catch (const std::exception& e) {
        std::cout << e.what();
    }
}
