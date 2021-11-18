#include "catch.hpp"

#include "client_connection.hpp"
#include "filesystem.hpp"
#include "generalAdmin.h"
#include "irods_at_scope_exit.hpp"
#include "irods_error_enum_matcher.hpp"
#include "irods_exception.hpp"
#include "rodsClient.h"
#include "user_administration.hpp"

#include "fmt/format.h"

namespace adm = irods::experimental::administration;
namespace fs = irods::experimental::filesystem;

namespace
{
    auto create_user_via_general_admin(RcComm& _comm,
                                       const char* _user_name,
                                       const char* _user_type,
                                       const char* _zone_name) -> int
    {
        const auto free_rerror = irods::at_scope_exit{[&_comm] {
            freeRErrorContent(_comm.rError);
        }};

        generalAdminInp_t inp{};

        inp.arg0 = "add";
        inp.arg1 = "user";
        inp.arg2 = _user_name;
        inp.arg3 = _user_type;
        inp.arg4 = _zone_name;
        //inp.arg5 = arg5;
        //inp.arg6 = arg6;
        //inp.arg7 = arg7;
        //inp.arg8 = arg8;
        //inp.arg9 = arg9;

        return rcGeneralAdmin(&_comm, &inp);
    } // create_user_via_general_admin

    auto remove_user_via_general_admin(RcComm& _comm,
                                       const char* _user_name,
                                       const char* _zone_name) -> int
    {
        const auto free_rerror = irods::at_scope_exit{[&_comm] {
            freeRErrorContent(_comm.rError);
        }};

        generalAdminInp_t inp{};

        inp.arg0 = "rm";
        inp.arg1 = "user";
        inp.arg2 = _user_name;
        inp.arg3 = _zone_name;
        //inp.arg4 = arg4;
        //inp.arg5 = arg5;
        //inp.arg6 = arg6;
        //inp.arg7 = arg7;
        //inp.arg8 = arg8;
        //inp.arg9 = arg9;

        return rcGeneralAdmin(&_comm, &inp);
    } // remove_user_via_general_admin
} // anonymous namespace

TEST_CASE("create_user")
{
    try {
        load_client_api_plugins();

        // Must be run as a rodsadmin
        irods::experimental::client_connection conn;
        RcComm& comm = static_cast<RcComm&>(conn);

        const auto home = [&comm](const std::string& _name) {
            return fs::path{fmt::format("/{}/home", comm.clientUser.rodsZone)};
        };

        const auto success = [&](const std::string& _name) -> bool {
            return adm::client::exists(comm, adm::user{_name}) &&
                   fs::client::exists(comm, home(_name) / _name);
        };

        const auto cleaned = [&](const std::string& _name) -> bool {
            return !adm::client::exists(comm, adm::user{_name}) &&
                   !fs::client::exists(comm, home(_name) / _name);
        };

        // make a user for local zone
        // -----------------------------------------
        // zone in username         zone in argument
        // 0                        0
        // 0                        1
        // 1                        0
        // 1                        1
        //
        // When zone is present in username and in argument, must test for matching
        SECTION("local_zone")
        {
            const char* local_zone = comm.clientUser.rodsZone;
            const auto name = "lzu";
            const auto name_with_zone = fmt::format("{}#{}", name, local_zone);

            REQUIRE(cleaned(name));

            // No zone name provided
            REQUIRE(0 == create_user_via_general_admin(comm, name, "rodsuser", nullptr));
            REQUIRE(success(name));
            REQUIRE(0 == remove_user_via_general_admin(comm, name, local_zone));
            REQUIRE(cleaned(name));

            REQUIRE(0 == create_user_via_general_admin(comm, name, "rodsuser", ""));
            REQUIRE(success(name));
            REQUIRE(0 == remove_user_via_general_admin(comm, name, local_zone));
            REQUIRE(cleaned(name));

            // Zone provided via argument, but not in username
            REQUIRE(0 == create_user_via_general_admin(comm, name, "rodsuser", local_zone));
            REQUIRE(success(name));
            REQUIRE(0 == remove_user_via_general_admin(comm, name, local_zone));
            REQUIRE(cleaned(name));

            // Zone provided in user name, but not in argument
            REQUIRE(0 == create_user_via_general_admin(comm, name_with_zone.data(), "rodsuser", nullptr));
            REQUIRE(success(name));
            REQUIRE(0 == remove_user_via_general_admin(comm, name, local_zone));
            REQUIRE(cleaned(name));

            REQUIRE(0 == create_user_via_general_admin(comm, name_with_zone.data(), "rodsuser", ""));
            REQUIRE(success(name));
            REQUIRE(0 == remove_user_via_general_admin(comm, name, local_zone));
            REQUIRE(cleaned(name));

            // Zone provided both in username and in argument
            REQUIRE(CAT_INVALID_ZONE == create_user_via_general_admin(comm, "lzu#nopes", "rodsuser", local_zone));
            REQUIRE(cleaned(name));

            REQUIRE(CAT_INVALID_ZONE == create_user_via_general_admin(comm, name_with_zone.data(), "rodsuser", "nopes"));
            REQUIRE(cleaned(name));
        } // local_zone

        // make a user for remote zone
        // -----------------------------------------
        // zone in username         zone in argument
        // 0                        0
        // 0                        1
        // 1                        0
        // 1                        1
        //
        // When zone is present in username and in argument, must test for matching
        SECTION("remote_zone")
        {
        }
    }
    catch (const irods::exception& e) {
        std::cout << e.client_display_what();
    }
    catch (const std::exception& e) {
        std::cout << e.what();
    }
} // rc_data_obj_open
