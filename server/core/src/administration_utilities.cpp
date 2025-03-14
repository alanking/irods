#include "irods/administration_utilities.hpp"

#include "irods/icatHighLevelRoutines.hpp"
#include "irods/irods_re_structs.hpp"
#include "irods/rodsConnect.h"
#include "irods/rodsUser.h"
#include "irods/user_validation_utilities.hpp"

#include <iterator>
#include <regex>

namespace
{
    auto user_is_client_or_proxy_user(const RsComm& _comm,
                                      const std::string_view _user_name,
                                      const std::string_view _zone_name) -> bool
    {
        const std::string_view zone_name = _zone_name.empty() ? getLocalZoneName() : _zone_name;

        if (_user_name == _comm.clientUser.userName && zone_name == _comm.clientUser.rodsZone) {
            return true;
        }

        if (_user_name == _comm.proxyUser.userName && zone_name == _comm.proxyUser.rodsZone) {
            return true;
        }

        return false;
    } // user_is_client_or_proxy_user
} // anonymous namespace

// TODO: use irods::experimental::administration namespace
// TODO: consider implementing a string/string_view wrapper which checks for nullptr
namespace irods
{
    auto create_user(RsComm& _comm,
                     const std::string_view _user_name,
                     const std::string_view _user_type,
                     const std::string_view _auth_string,
                     const std::string_view _zone_name) -> int
    {
        if (!irods::user::type_is_valid(_user_type)) {
            return CAT_INVALID_USER_TYPE;
        }

        const auto user_and_zone_name = irods::user::validate_name(_user_name);
        if (!user_and_zone_name) {
            return USER_INVALID_USERNAME_FORMAT;
        }

        const auto& [user_name, zone_name] = *user_and_zone_name;

        // If the zone name is provided both via argument in the admin API and in the username,
        // they must match. The zone name is used in the user name to identify the home zone of
        // each user.
        if (!_zone_name.empty() && !zone_name.empty() && _zone_name != zone_name) {
            return CAT_INVALID_ZONE;
        }

        const auto& local_zone_name = getLocalZoneName();

        const auto user_zone_name_is_remote = !zone_name.empty() &&
                                              zone_name != local_zone_name;

        const auto arg_zone_name_is_remote = !_zone_name.empty() &&
                                             _zone_name != local_zone_name;

        // Remote groups are not allowed. If the provided zone name in either the
        // administration API argument or the username is a remote zone, return an error.
        if (_user_type == "rodsgroup" && (user_zone_name_is_remote || arg_zone_name_is_remote)) {
            constexpr auto err = SYS_NOT_ALLOWED;
            addRErrorMsg(&_comm.rError, err, "groups cannot be made for a remote zone");
            return err;
        }

        userInfo_t ui{};
        std::strncpy(ui.userType, _user_type.data(), sizeof(ui.userType));
        std::strncpy(ui.authInfo.authStr, _auth_string.data(), sizeof(ui.authInfo.authStr));

        // The database plugin has a very specific expectation for how the data should arrive,
        // so set the zone to an empty string, and the user name should only contain the zone
        // name if the zone is remote. The passed-in user name contains the zone name if the
        // zone name was parsed by the validator.
        if (!zone_name.empty() && zone_name != getLocalZoneName()) {
            std::strncpy(ui.userName, _user_name.data(), sizeof(ui.userName));
        }
        else {
            std::strncpy(ui.userName, user_name.data(), sizeof(ui.userName));
        }

        // The zone name is a parameter in both the General Admin and User Admin APIs, so copy
        // the value into the rodsZone buffer if it was passed along.
        if (!_zone_name.empty()) {
            std::strncpy(ui.rodsZone, _zone_name.data(), sizeof(ui.rodsZone));
        }

        ruleExecInfo_t rei{};
        rei.rsComm = &_comm;
        rei.uoio = &ui;
        rei.uoic = &_comm.clientUser;
        rei.uoip = &_comm.proxyUser;

        if (const auto ec = applyRuleArg("acCreateUser", nullptr, 0, &rei, SAVE_REI); ec != 0) {
            chlRollback(&_comm);
            return ec;
        }

        return 0;
    } // create_user

    auto remove_user(RsComm& _comm,
                     const std::string_view _user_name,
                     const std::string_view _zone_name) -> int
    {
        const auto user_and_zone_name = irods::user::validate_name(_user_name);
        if (!user_and_zone_name) {
            return USER_INVALID_USERNAME_FORMAT;
        }

        const auto& [user_name, zone_name] = *user_and_zone_name;

        // If the zone name is provided both via argument in the admin API and in the username,
        // they must match. The zone name is used in the user name to identify the home zone of
        // each user.
        if (!_zone_name.empty() && !zone_name.empty() && _zone_name != zone_name) {
            return CAT_INVALID_ZONE;
        }

        if (user_is_client_or_proxy_user(_comm, user_name, zone_name)) {
            constexpr auto err = SYS_NOT_ALLOWED;
            addRErrorMsg(&_comm.rError, err,
                         "cannot remove currently authenticated client or proxy user");
            return err;
        }

        userInfo_t ui{};

        // The database plugin has a very specific expectation for how the data should arrive,
        // so set the zone to an empty string, and the user name should only contain the zone
        // name if the zone is remote. The passed-in user name contains the zone name if the
        // zone name was parsed by the validator.
        if (!zone_name.empty() && zone_name != getLocalZoneName()) {
            std::strncpy(ui.userName, _user_name.data(), sizeof(ui.userName));
        }
        else {
            std::strncpy(ui.userName, user_name.data(), sizeof(ui.userName));
        }

        userInfo_t uir = ui;
        if (!_zone_name.empty()) {
            std::strncpy(uir.rodsZone, _zone_name.data(), sizeof(ui.rodsZone));
        }
        else if (!zone_name.empty()) {
            std::strncpy(uir.rodsZone, zone_name.data(), sizeof(uir.rodsZone));
        }

        ruleExecInfo_t rei{};
        rei.rsComm = &_comm;
        rei.uoio = &uir;
        rei.uoic = &_comm.clientUser;
        rei.uoip = &_comm.proxyUser;

        if (const auto ec = applyRuleArg("acDeleteUser", nullptr, 0, &rei, SAVE_REI); ec != 0) {
            chlRollback(&_comm);
            return ec;
        }

        return 0;
    } // remove_user

    auto is_zone_name_valid(const std::string_view _zone_name) -> bool
    {
        // TODO(#8175): Use the regex/pattern from the JSON schema file to avoid drift.
        static std::regex regex{R"(^[A-Za-z0-9_\.]+$)"};
        return std::regex_match(std::begin(_zone_name), std::end(_zone_name), regex);
    } // is_zone_name_valid
} // namespace irods
