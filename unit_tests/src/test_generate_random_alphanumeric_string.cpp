#include <catch2/catch.hpp>

#include "irods/irods_exception.hpp"
#include "irods/irods_random.hpp"

#include <algorithm>
#include <cctype>
#include <string>

TEST_CASE("length of 0 results in an empty string")
{
    CHECK(irods::generate_random_alphanumeric_string(0).empty());
}

TEST_CASE("length of 1 effectively calls generate_random_alphanumeric_character")
{
    constexpr std::size_t character_count = 1;
    const auto s = irods::generate_random_alphanumeric_string(character_count);
    REQUIRE(!s.empty());
    CHECK(s.size() == character_count);
    CHECK(std::all_of(std::begin(s), std::end(s), [](const auto& c) { return std::isalnum(c); }));
}

TEST_CASE("only alphanumeric characters appear in string of statistically significant length")
{
    constexpr std::size_t character_count = 1'000'000;
    const auto s = irods::generate_random_alphanumeric_string(character_count);
    REQUIRE(!s.empty());
    CHECK(s.size() == character_count);
    CHECK(std::all_of(std::begin(s), std::end(s), [](const auto& c) { return std::isalnum(c); }));
}
