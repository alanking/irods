#ifndef VOTING_HPP
#define VOTING_HPP

#include "irods/irods_plugin_context.hpp"
#include "irods/irods_resource_plugin.hpp"
#include "irods/irods_resource_redirect.hpp"

#include <string_view>

namespace irods::experimental::resource::voting {

namespace vote {
    constexpr float high{1.0};
    constexpr float medium{0.5};
    constexpr float low{0.25};
    constexpr float zero{0.0};
}

float calculate(
    std::string_view op,
    irods::plugin_context& ctx,
    std::string_view curr_host,
    const irods::hierarchy_parser& parser);

/// \brief Compare two votes to see if they are equal.
///
/// This function exists because comparing floating point values is fraught with peril.
/// See: https://isocpp.org/wiki/faq/newbie#floating-point-arith
///
/// \param[in] _lhs The vote against which \p _rhs is being compared.
/// \param[in] _rhs The vote against which \p _lhs is being compared.
///
/// \retval true If \p _lhs and \p _rhs are considered equal.
/// \retval false If \p _lhs and \p _rhs are not considered equal.
///
/// \since 4.2.12
auto is_equal(float _lhs, float _rhs) -> bool;

} // namespace irods::experimental::resource::voting

#endif // VOTING_HPP
