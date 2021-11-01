#ifndef IRODS_SAFE_STRING_HPP
#define IRODS_SAFE_STRING_HPP

#include <string>
#include <string_view>

namespace irods::experimental::safe
{
    template<class CharT>
    struct basic_string
    {
        std::basic_string<CharT> value;

        basic_string() = default;

        basic_string(const CharT* _s)
            : value{_s ? _s : ""}
        {
        }

        basic_string(const std::basic_string<CharT>& _s)
            : value{_s}
        {
        }

        basic_string(const std::basic_string_view<CharT> _s)
            : value{_s.data()}
        {
        }
    };

    template<class CharT>
    struct basic_string_view
    {
        std::basic_string_view<CharT> value;

        basic_string_view() = default;

        basic_string_view(const CharT* _s)
            : value{_s ? _s : ""}
        {
        }

        basic_string_view(const std::basic_string_view<CharT> _s)
            : value{_s}
        {
        }

        basic_string_view(const std::basic_string<CharT>& _s)
            : value{_s}
        {
        }
    };

    using string_view = basic_string_view<char>;
    using string = basic_string<char>;
} // namespace irods::experimental::safe

#endif // IRODS_SAFE_STRING_HPP
