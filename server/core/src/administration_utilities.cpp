#include "administration_utilities.hpp"
#include "icatHighLevelRoutines.hpp"
#include "irods_re_structs.hpp"
#include "rodsConnect.h"
#include "rodsUser.h"
#include "user_validation_utilities.hpp"

// TODO: use irods::experimental::administration namespace
// TODO: consider implementing a string/string_view wrapper which checks for nullptr
namespace irods
{
    auto create_user(RsComm& _comm,
                     const std::string_view _user_name,
                     const std::string_view _zone_name,
                     const std::string_view _user_type,
                     const std::string_view _auth_string) -> int
    {
        if (!irods::user::type_is_valid(_user_type)) {
            return CAT_INVALID_USER_TYPE;
        }

        const auto user_and_zone_name = irods::user::validate_name(_user_name);
        if (!user_and_zone_name) {
            return USER_INVALID_USERNAME_FORMAT;
        }

        const auto& [user_name, zone_name] = *user_and_zone_name;

        if (_user_type == "rodsgroup" && !zone_name.empty() && zone_name != getLocalZoneName()) {
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

    auto remove_user(RsComm& _comm, const std::string_view _user_name) -> int
    {
        const auto user_and_zone_name = irods::user::validate_name(_user_name);
        if (!user_and_zone_name) {
            return USER_INVALID_USERNAME_FORMAT;
        }

        const auto& [user_name, zone_name] = *user_and_zone_name;

        if (user_name == _comm.clientUser.userName || user_name == _comm.proxyUser.userName) {
            return CANNOT_REMOVE_CLIENTUSER_OR_PROXYUSER;
        }

        userInfo_t ui{};
        if (!zone_name.empty() && zone_name != getLocalZoneName()) {
            std::strncpy(ui.userName, _user_name.data(), sizeof(ui.userName));
        }
        else {
            std::strncpy(ui.userName, user_name.data(), sizeof(ui.userName));
        }

        userInfo_t uir = ui;
        if (!zone_name.empty()) {
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
} // namespace irods
