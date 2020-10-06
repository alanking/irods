#include "catch.hpp"

#include "irods_error_enum_matcher.hpp"
#include "rodsClient.h"

#include "client_connection.hpp"
#include "data_object_finalize.h"
#include "data_object_proxy.hpp"
#include "dataObjRepl.h"
#include "dstream.hpp"
#include "filesystem.hpp"
#include "irods_at_scope_exit.hpp"
#include "logical_locking.hpp"
#include "replica.hpp"
#include "replica_proxy.hpp"
#include "resource_administration.hpp"
#include "transport/default_transport.hpp"
#include "unit_test_utils.hpp"

#include "json.hpp"
#include "fmt/format.h"

#include <chrono>
#include <iostream>
#include <thread>

namespace adm = irods::experimental::administration;
namespace fs = irods::experimental::filesystem;
namespace io = irods::experimental::io;
namespace replica = irods::experimental::replica;

using json = nlohmann::json;

namespace
{
    auto open_replica_for_read(RcComm& _comm, std::string_view _logical_path, std::string_view _hierarchy) -> int
    {
        dataObjInp_t open_inp{};
        auto cond_input = irods::experimental::key_value_proxy(open_inp.condInput);

        std::snprintf(open_inp.objPath, _logical_path.length() + 1, "%s", _logical_path.data());

        open_inp.openFlags = O_RDONLY;

        cond_input[RESC_NAME_KW] = _hierarchy;

        return rcDataObjOpen(&_comm, &open_inp);
    } // open_replica_for_read

    auto open_replica_for_write(RcComm& _comm, std::string_view _logical_path, std::string_view _hierarchy) -> int
    {
        dataObjInp_t open_inp{};
        auto cond_input = irods::experimental::key_value_proxy(open_inp.condInput);

        std::snprintf(open_inp.objPath, _logical_path.length() + 1, "%s", _logical_path.data());

        open_inp.openFlags = O_WRONLY;

        cond_input[RESC_NAME_KW] = _hierarchy;

        return rcDataObjOpen(&_comm, &open_inp);
    } // open_replica_for_write

    auto read_replica(RcComm& _comm, const int _fd, char* _buf, const size_t _len) -> int
    {
        openedDataObjInp_t read_inp{};
        read_inp.l1descInx = _fd;
        read_inp.len = _len;

        bytesBuf_t bbuf{};
        bbuf.buf = _buf;
        bbuf.len = _len;

        return rcDataObjRead(&_comm, &read_inp, &bbuf);
    } // read_replica

    auto write_replica(RcComm& _comm, const int _fd, std::string_view _contents) -> int
    {
        char buf[1024]{};
        std::snprintf(buf, sizeof(buf), "%s", _contents.data());

        openedDataObjInp_t write_inp{};
        write_inp.l1descInx = _fd;
        write_inp.len = sizeof(buf);

        bytesBuf_t bbuf{};
        bbuf.buf = buf;
        bbuf.len = sizeof(buf);

        return rcDataObjWrite(&_comm, &write_inp, &bbuf);
    } // write_replica

    auto close_replica(RcComm& _comm, const int _fd, const int _bytes_moved) -> int
    {
        openedDataObjInp_t close_inp{};
        close_inp.l1descInx = _fd;
        close_inp.len = _bytes_moved;

        return rcDataObjClose(&_comm, &close_inp);
    } // close_replica
} // anonymous namespace

TEST_CASE("logical locking", "[logical_locking]")
{
    using namespace std::string_literals;
    using namespace std::chrono_literals;

    load_client_api_plugins();

    // create two resources onto which a data object can be written
    const std::string resc_0 = "resc_0";
    const std::string resc_1 = "resc_1";

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

    REQUIRE(std::get<bool>(adm::client::resource_exists(comm, resc_0)));
    REQUIRE(std::get<bool>(adm::client::resource_exists(comm, resc_1)));

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

    std::string_view object_content = "testing";

    {
        io::client::default_transport tp{comm};
        io::odstream{tp, target_object, io::root_resource_name{resc_0}} << object_content;
    }

    REQUIRE(replica::replica_exists(comm, target_object, resc_0));
    CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_0));

    REQUIRE(unit_test_utils::replicate_data_object(comm, target_object.c_str(), resc_1));

    REQUIRE(replica::replica_exists(comm, target_object, resc_1));
    CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_1));

    SECTION("open for read with two replicas")
    {
        char buf_0[1024]{};

        const int fd_0 = open_replica_for_read(comm, target_object.c_str(), resc_0);
        REQUIRE(fd_0 > 2);
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));

        {
            irods::experimental::client_connection another_conn;
            RcComm& another_comm = static_cast<RcComm&>(another_conn);
            CHECK(DATA_OBJECT_LOCKED == open_replica_for_write(another_comm, target_object.c_str(), resc_1));
            CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
            CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));
        }

        const int bytes_read_0 = read_replica(comm, fd_0, buf_0, sizeof(buf_0));
        CHECK(static_cast<int>(object_content.length()) == bytes_read_0);

        REQUIRE(close_replica(comm, fd_0, bytes_read_0) >= 0);

        // ensure that the reads were successful
        CHECK(object_content == buf_0);

        // ensure that the read lock was removed and statuses were corrected
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_0));
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_1));
    }

    SECTION("open for write with two replicas")
    {
        const int fd_0 = open_replica_for_write(comm, target_object.c_str(), resc_0);
        REQUIRE(fd_0 > 2);
        CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, resc_0));
        CHECK(WRITE_LOCK == replica::replica_status(comm, target_object, resc_1));

        {
            irods::experimental::client_connection another_conn;
            RcComm& another_comm = static_cast<RcComm&>(another_conn);
            CHECK(DATA_OBJECT_LOCKED == open_replica_for_read(another_comm, target_object.c_str(), resc_1));
            CHECK(INTERMEDIATE_REPLICA == replica::replica_status(comm, target_object, resc_0));
            CHECK(WRITE_LOCK == replica::replica_status(comm, target_object, resc_1));
        }

        std::string_view new_value = "new value";
        const int bytes_written_0 = write_replica(comm, fd_0, new_value);
        CHECK(static_cast<int>(new_value.length()) == bytes_written_0);

        REQUIRE(close_replica(comm, fd_0, bytes_written_0) >= 0);

        // ensure that the read lock was removed and statuses were corrected
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_0));
        CHECK(STALE_REPLICA == replica::replica_status(comm, target_object, resc_1));
    }

#if 0
    SECTION("simultaneous open for read")
    {
        char buf_0[1024]{};
        char buf_1[1024]{};

        const int fd_0 = open_replica_for_read(comm, target_object.c_str(), resc_0);
        REQUIRE(fd_0 > 2);
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));

        const int fd_1 = open_replica_for_read(comm, target_object.c_str(), resc_1);
        REQUIRE(fd_1 > 2);
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));

        const int bytes_read_0 = read_replica(comm, fd_0, buf_0, sizeof(buf_0));
        REQUIRE(static_cast<int>(object_content.length()) == bytes_read_0);

        const int bytes_read_1 = read_replica(comm, fd_1, buf_1, sizeof(buf_1));
        REQUIRE(static_cast<int>(object_content.length()) == bytes_read_1);

        REQUIRE(close_replica(comm, fd_0, bytes_read_0) >= 0);

        // ensure that the object remains in read lock (replica 1 still open left)
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
        CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));

        REQUIRE(close_replica(comm, fd_1, bytes_read_1) >= 0);

        // ensure that the read lock was removed and statuses were corrected
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_0));
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_1));

        // ensure that the reads were successful
        CHECK(object_content == buf_0);
        CHECK(object_content == buf_1);
    }

    SECTION("simultaneous open for read")
    {
        char buf_0[1024]{};
        char buf_1[1024]{};

        {
            io::client::default_transport tp_1{comm};
            io::idstream stream_1{tp_1, target_object, io::root_resource_name{resc_0}};
            REQUIRE(stream_1);
            CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
            CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));

            {
                io::client::default_transport tp_2{comm};
                io::idstream stream_2{tp_2, target_object, io::root_resource_name{resc_0}};
                REQUIRE(stream_2);
                CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
                CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));

                // read into the buffers
                stream_1.read(buf_0, object_content.length());
                stream_2.read(buf_1, object_content.length());
            }

            // ensure that read lock is still in effect
            CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_0));
            CHECK(READ_LOCK == replica::replica_status(comm, target_object, resc_1));
        }

        // ensure that the reads were successful
        CHECK(object_content == buf_0);
        CHECK(object_content == buf_1);

        // ensure that all replica states have been restored
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_0));
        CHECK(GOOD_REPLICA == replica::replica_status(comm, target_object, resc_1));
    }
#endif
}

