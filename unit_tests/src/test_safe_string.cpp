#include "catch.hpp"

#include "safe_string.hpp"

namespace is = irods::experimental::safe;

namespace
{
    template<typename safe_string>
    auto test_constructor_with_empty_value() -> void
    {
        CHECK(safe_string{}.value        == "");
        CHECK(safe_string{""}.value      == "");
        CHECK(safe_string{"\0"}.value    == "");
        CHECK(safe_string{nullptr}.value == "");
    }

    template<typename safe_string, typename string_type>
    auto test_wrapped_type_constructor(const string_type& _s = {}) -> void
    {
        CHECK(safe_string{_s}.value == _s);
    }

    template<typename safe_string, typename CharT>
    auto test_ptr_constructor(const CharT* _s = nullptr) -> void
    {
        CHECK(safe_string{_s}.value == _s);
    }
}

TEST_CASE("irods_safe_string_constructors")
{
    test_constructor_with_empty_value<is::string>();
    test_wrapped_type_constructor<is::string, std::string>();
    test_wrapped_type_constructor<is::string, std::string_view>();

    test_constructor_with_empty_value<is::string_view>();
    test_wrapped_type_constructor<is::string_view, std::string>();
    test_wrapped_type_constructor<is::string_view, std::string_view>();

    test_ptr_constructor<is::string>();
    test_ptr_constructor<is::string_view>();
}
