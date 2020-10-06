#include "catch.hpp"

#include "replica_state_table.hpp"
#include "irods_at_scope_exit.hpp"

#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

using state_type = irods::experimental::replica_state_table::state_type;
namespace data_object = irods::experimental::data_object;

constexpr int REPLICA_COUNT       = 3;
constexpr std::uint64_t SIZE_1    = 4000;
constexpr std::uint64_t SIZE_2    = 9999;
constexpr std::uint64_t DATA_ID_1 = 10101;
constexpr std::uint64_t DATA_ID_2 = 20202;
const std::string LOGICAL_PATH_1  = "/tempZone/home/rods/foo";

TEST_CASE("replica state table", "[basic]")
{
    // simulate creation of some replicas in the catalog
    std::array<DataObjInfo*, REPLICA_COUNT> replicas;

    DataObjInfo* head{};
    {
        DataObjInfo* prev{};
        for (int i = 0; i < REPLICA_COUNT; ++i) {
            auto [proxy, lm] = irods::experimental::replica::make_replica_proxy();
            proxy.logical_path(LOGICAL_PATH_1);
            proxy.size(SIZE_1);
            proxy.replica_number(i);
            proxy.data_id(DATA_ID_1);

            DataObjInfo* curr = lm.release();
            if (!head) {
                head = curr;
            }
            else {
                prev->next = curr;
            }
            prev = curr;
            replicas[i] = curr;

            const auto& r = replicas[i];
            REQUIRE(LOGICAL_PATH_1 == r->objPath);
            REQUIRE(DATA_ID_1      == r->dataId);
            REQUIRE(i              == r->replNum);
            REQUIRE(SIZE_1         == r->dataSize);
        }
    }

    // ensure that the linked list is valid and will be freed upon exit
    REQUIRE(head);
    const auto replica_list_lm = irods::experimental::lifetime_manager{*head};

    // create data_object_proxy from the linked list and instantiate the Singleton
    auto obj = data_object::make_data_object_proxy(*head);

    auto& rst = irods::experimental::replica_state_table::instance();

    // create before entry for the data object
    REQUIRE_NOTHROW(rst.insert(obj));
    REQUIRE(rst.contains(LOGICAL_PATH_1));

    // ensure that information matches
    {
        auto before = rst.at(LOGICAL_PATH_1, state_type::before);

        for (int i = 0; i < REPLICA_COUNT; ++i) {
            const auto& state_table_replica = before.replicas().at(i);
            const auto original_replica = irods::experimental::replica::make_replica_proxy(*replicas.at(i));
            CHECK(state_table_replica.data_id()        == original_replica.data_id());
            CHECK(state_table_replica.logical_path()   == original_replica.logical_path());
            CHECK(state_table_replica.replica_number() == original_replica.replica_number());
            CHECK(state_table_replica.size()           == original_replica.size());

            // this should be a copy of the replica states
            CHECK(state_table_replica.get()            != original_replica.get());
        }
    }

    SECTION("modify before entry")
    {
        // get before state and preserve for testing values later
        auto before = rst.at(LOGICAL_PATH_1, state_type::before);
        const auto [original_before, original_before_lm] = data_object::duplicate_data_object(before);

        // modify items in the before state by manipulating the replica_state_table
        before.data_id(DATA_ID_2);
        before.replicas().at(1).size(SIZE_2);

        // get before and after state for testing values
        const auto& [modified_before, unmodified_after] = rst.at(LOGICAL_PATH_1);

        for (int i = 0; i < REPLICA_COUNT; ++i) {
            const auto& original_before_replica  = original_before.replicas().at(i);
            const auto& modified_before_replica  = modified_before.replicas().at(i);
            const auto& unmodified_after_replica = unmodified_after.replicas().at(i);
            const auto& local_before_replica     = before.replicas().at(i);

            CHECK(original_before_replica.data_id() == unmodified_after_replica.data_id());
            CHECK(original_before_replica.size()    == unmodified_after_replica.size());

            CHECK(modified_before_replica.data_id() == local_before_replica.data_id());
            CHECK(modified_before_replica.size()    == local_before_replica.size());
        }
    }

    SECTION("track multiple data objects")
    {
        std::array<DataObjInfo*, REPLICA_COUNT> replicas_2;

        const std::string LOGICAL_PATH_2  = "/tempZone/home/rods/goo";

        DataObjInfo* head_2{};
        DataObjInfo* prev{};
        for (int i = 0; i < REPLICA_COUNT; ++i) {
            auto [proxy, lm] = irods::experimental::replica::make_replica_proxy();
            proxy.logical_path(LOGICAL_PATH_2);
            proxy.size(SIZE_2);
            proxy.replica_number(i);
            proxy.data_id(DATA_ID_2);

            DataObjInfo* curr = lm.release();
            if (!head_2) {
                head_2 = curr;
            }
            else {
                prev->next = curr;
            }
            prev = curr;
            replicas_2[i] = curr;

            const auto& r = replicas_2[i];
            REQUIRE(LOGICAL_PATH_2 == r->objPath);
            REQUIRE(DATA_ID_2      == r->dataId);
            REQUIRE(i              == r->replNum);
            REQUIRE(SIZE_2         == r->dataSize);
        }

        // ensure that the linked list is valid and will be freed upon exit
        REQUIRE(head_2);
        const auto replica_list_2_lm = irods::experimental::lifetime_manager{*head_2};

        auto obj_2 = data_object::make_data_object_proxy(*head_2);
        REQUIRE_NOTHROW(rst.insert(obj_2));
        REQUIRE(rst.contains(LOGICAL_PATH_2));

        {
            auto before = rst.at(LOGICAL_PATH_2, state_type::before);

            for (int i = 0; i < REPLICA_COUNT; ++i) {
                const auto& state_table_replica = before.replicas().at(i);
                const auto original_replica = irods::experimental::replica::make_replica_proxy(*replicas_2.at(i));
                CHECK(state_table_replica.data_id()        == original_replica.data_id());
                CHECK(state_table_replica.logical_path()   == original_replica.logical_path());
                CHECK(state_table_replica.replica_number() == original_replica.replica_number());
                CHECK(state_table_replica.size()           == original_replica.size());

                // this should be a copy of the replica states
                CHECK(state_table_replica.get()            != original_replica.get());
            }
        }

        CHECK_NOTHROW(rst.erase(LOGICAL_PATH_2));
    }

    // ref_count -> 0
    CHECK_NOTHROW(rst.erase(LOGICAL_PATH_1));
    CHECK(!rst.contains(LOGICAL_PATH_1));
    rst.deinit();
}

TEST_CASE("invalid_keys", "[basic]")
{
    DataObjInfo info{};
    auto obj = data_object::make_data_object_proxy(info);
    auto& rst = irods::experimental::replica_state_table::instance();
    CHECK_FALSE(rst.contains("nope"));
    CHECK_THROWS(rst.at("nope"));
    CHECK_THROWS(rst.set("nope", obj));
    CHECK_THROWS(rst.erase("nope"));
}

