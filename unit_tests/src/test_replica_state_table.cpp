#include "catch.hpp"

#include "replica_state_table.hpp"
#include "irods_at_scope_exit.hpp"

#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

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
    auto obj = irods::experimental::data_object::make_data_object_proxy(*head);

    auto& rst = irods::experimental::replica_state_table::instance();

    // create before entry for the data object
    REQUIRE_NOTHROW(rst.create_entry(obj));
    REQUIRE(rst.contains(LOGICAL_PATH_1));

    REQUIRE(std::nullopt == rst.get_data_object_state(LOGICAL_PATH_1, irods::experimental::replica_state_table::state_type::after));
    REQUIRE_THROWS(rst.create_entry(obj));

    // ensure that information matches
    {
        auto before = rst.get_data_object_state(LOGICAL_PATH_1);
        REQUIRE(before);
        for (int i = 0; i < REPLICA_COUNT; ++i) {
            const auto& state_table_replica = before->replicas().at(i);
            const auto original_replica = irods::experimental::replica::make_replica_proxy(*replicas.at(i));
            CHECK(state_table_replica.data_id()        == original_replica.data_id());
            CHECK(state_table_replica.logical_path()   == original_replica.logical_path());
            CHECK(state_table_replica.replica_number() == original_replica.replica_number());
            CHECK(state_table_replica.size()           == original_replica.size());

            // this should be a copy of the replica states
            CHECK(state_table_replica.get()            != original_replica.get());
        }
    }

    SECTION("add after entry")
    {
        auto before = rst.get_data_object_state(LOGICAL_PATH_1);
        REQUIRE(before);

        // set some new info and place in the after slot
        obj.data_id(DATA_ID_2);
        obj.replicas().at(1).size(SIZE_2);
        REQUIRE_NOTHROW(rst.set_data_object_state(LOGICAL_PATH_1, obj));

        auto after = rst.get_data_object_state(LOGICAL_PATH_1, irods::experimental::replica_state_table::state_type::after);
        REQUIRE(after);

        for (int i = 0; i < REPLICA_COUNT; ++i) {
            const auto& before_replica = before->replicas().at(i);
            const auto& after_replica = after->replicas().at(i);
            CHECK(before_replica.data_id()  == DATA_ID_1);
            CHECK(after_replica.data_id()   == DATA_ID_2);
            CHECK(before_replica.size()     == SIZE_1);
            CHECK(after_replica.size()      == (1 == i ? SIZE_2 : SIZE_1));
        }
    }

    SECTION("modify before entry")
    {
        auto original_before_tmp = rst.get_data_object_state(LOGICAL_PATH_1);
        REQUIRE(original_before_tmp);
        auto [original_before, original_before_lm] = irods::experimental::data_object::duplicate_data_object(*original_before_tmp);

        // set some new info and place in the after slot
        obj.data_id(DATA_ID_2);
        obj.replicas().at(1).size(SIZE_2);
        REQUIRE_NOTHROW(rst.set_data_object_state(LOGICAL_PATH_1, obj, irods::experimental::replica_state_table::state_type::before));

        auto modified_before_tmp = rst.get_data_object_state(LOGICAL_PATH_1);
        REQUIRE(modified_before_tmp);

        auto [modified_before, modified_before_lm] = irods::experimental::data_object::duplicate_data_object(*modified_before_tmp);

        for (int i = 0; i < REPLICA_COUNT; ++i) {
            const auto& original_before_replica = original_before.replicas().at(i);
            const auto& modified_before_replica = modified_before.replicas().at(i);
            CHECK(original_before_replica.data_id() == DATA_ID_1);
            CHECK(original_before_replica.size()    == SIZE_1);
            CHECK(modified_before_replica.data_id() == DATA_ID_2);
            CHECK(modified_before_replica.size()    == (1 == i ? SIZE_2 : SIZE_1));
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

        auto obj_2 = irods::experimental::data_object::make_data_object_proxy(*head_2);
        REQUIRE_NOTHROW(rst.create_entry(obj_2));
        REQUIRE(rst.contains(LOGICAL_PATH_2));

        {
            auto before = rst.get_data_object_state(LOGICAL_PATH_2);
            REQUIRE(before);
            for (int i = 0; i < REPLICA_COUNT; ++i) {
                const auto& state_table_replica = before->replicas().at(i);
                const auto original_replica = irods::experimental::replica::make_replica_proxy(*replicas_2.at(i));
                CHECK(state_table_replica.data_id()        == original_replica.data_id());
                CHECK(state_table_replica.logical_path()   == original_replica.logical_path());
                CHECK(state_table_replica.replica_number() == original_replica.replica_number());
                CHECK(state_table_replica.size()           == original_replica.size());

                // this should be a copy of the replica states
                CHECK(state_table_replica.get()            != original_replica.get());
            }
        }

        REQUIRE_NOTHROW(rst.erase_entry(LOGICAL_PATH_2));
    }

    REQUIRE_NOTHROW(rst.erase_entry(LOGICAL_PATH_1));
    rst.deinit();
}

TEST_CASE("invalid_keys", "[basic]")
{
    DataObjInfo info{};
    auto obj = irods::experimental::data_object::make_data_object_proxy(info);
    auto& rst = irods::experimental::replica_state_table::instance();
    REQUIRE(!rst.contains("nope"));
    REQUIRE(std::nullopt == rst.get_data_object_state("nope"));
    REQUIRE_THROWS(rst.set_data_object_state("nope", obj));
    REQUIRE_THROWS(rst.erase_entry("nope"));
}

