#include "catch.hpp"

#include "irods_error_enum_matcher.hpp"
#include "rodsClient.h"

#include "client_connection.hpp"
#include "filesystem.hpp"

#include "fmt/format.h"
#include <iostream>

namespace fs = irods::experimental::filesystem;

    //dataObjInp_t
        //char objPath[MAX_NAME_LEN];
        //int createMode;
        //int openFlags;      /* used for specCollInx in rcQuerySpecColl */
        //rodsLong_t offset;
        //rodsLong_t dataSize;
        //int numThreads;
        //int oprType;
        //specColl_t *specColl;
        //keyValPair_t condInput;   /* include chksum flag and value */
    //openedDataObjInp_t
        //int l1descInx;              /* for read, write, close */
        //int len;                    /* length of operation for read, write */
        //int whence;                 /* used for lseek */
        //int oprType;
        //rodsLong_t offset;
        //rodsLong_t bytesWritten;    /* for close */
        //keyValPair_t condInput;   /* include chksum flag and value */

namespace
{
    auto create_empty_replica(const fs::path& _path)
    {
        std::string_view path_str = _path.c_str();

        irods::experimental::client_connection conn;
        RcComm& comm = static_cast<RcComm&>(conn);

        dataObjInp_t open_inp{};
        std::snprintf(open_inp.objPath, path_str.length(), "%s", path_str.data());
        open_inp.openFlags = O_CREAT | O_TRUNC | O_WRONLY;
        const auto fd = rcDataObjOpen(&comm, &open_inp);
        REQUIRE(fd > 2);
        CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, _path, 0));

        openedDataObjInp_t close_inp{};
        close_inp.l1descInx = fd;
        REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);
        REQUIRE(GOOD_REPLICA == replica::replica_status(comm, _path, 0));
    } // create_empty_replica
} // anonymous namespace

TEST_CASE("test rcDataObjOpen and rcDataObjClose")
{
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

    SECTION("create with no bytes")
    {
        create_empty_replica(target_object);
    }

    SECTION("create with no close")
    {
        std::string_view path_str = target_object.c_str();

        {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            dataObjInp_t open_inp{};
            std::snprintf(open_inp.objPath, path_str.length(), "%s", path_str.data());
            open_inp.openFlags = O_CREAT | O_TRUNC | O_WRONLY;
            const auto fd = rcDataObjOpen(&comm, &open_inp);
            REQUIRE(fd > 2);
            CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
        }

        CHECK(STALE_REPLICA == replica::replica_status(comm, target_object, 0));
    }

    SECTION("open for write with no bytes")
    {
        create_empty_replica(target_object);

        irods::experimental::client_connection conn;
        RcComm& comm = static_cast<RcComm&>(conn);

        dataObjInp_t open_inp{};
        std::snprintf(open_inp.objPath, path_str.length(), "%s", path_str.data());
        open_inp.openFlags = O_WRONLY;
        const auto fd = rcDataObjOpen(&comm, &open_inp);
        REQUIRE(fd > 2);
        CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));

        openedDataObjInp_t close_inp{};
        close_inp.l1descInx = fd;
        REQUIRE(rcDataObjClose(&comm, &close_inp) >= 0);
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, 0));
    }

    SECTION("open for write with no close")
    {
        create_empty_replica(target_object);

        {
            irods::experimental::client_connection conn;
            RcComm& comm = static_cast<RcComm&>(conn);

            dataObjInp_t open_inp{};
            std::snprintf(open_inp.objPath, path_str.length(), "%s", path_str.data());
            open_inp.openFlags = O_WRONLY;
            const auto fd = rcDataObjOpen(&comm, &open_inp);
            REQUIRE(fd > 2);
            CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, 0));
        }

        CHECK(STALE_REPLICA == replica::replica_status(comm, target_object, 0));
    }
}
