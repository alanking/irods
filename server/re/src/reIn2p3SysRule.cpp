/**
 * @file  reIn2p3SysRule.cpp
 */

#include "irods/reIn2p3SysRule.hpp"

#include "irods/irods_configuration_keywords.hpp"
#include "irods/irods_logger.hpp"
#include "irods/rodsErrorTable.h"
#include "irods/rsGenQuery.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace
{
    using log_svr = irods::experimental::log::server;
} // anonymous namespace

std::int16_t threadIsAlive[MAX_NSERVERS]; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

int checkHostAccessControl(const std::string& _user_name,
                           const std::string& _client_host,
                           const std::string& _groups_name)
{
    log_svr::debug(
        "{}: Checking if user is allowed to access server: _user_name=[{}], _client_host=[{}], _groups_name=[{}]",
        __func__,
        _user_name,
        _client_host,
        _groups_name);

    namespace ip = boost::asio::ip;

    std::vector<std::string> group_list;
    boost::split(group_list, _groups_name, boost::is_any_of("\t "), boost::token_compress_on);

    const auto host_access_control = irods::get_server_property<nlohmann::json>(irods::KW_CFG_HOST_ACCESS_CONTROL);
    const auto& access_entries = host_access_control.at(irods::KW_CFG_ACCESS_ENTRIES);

    try {
        for (const auto& access_entry : access_entries) {
            try {
                const auto& user = access_entry.at(irods::KW_CFG_USER).get_ref<const std::string&>();
                const auto& group = access_entry.at(irods::KW_CFG_GROUP).get_ref<const std::string&>();
                const auto& addy = access_entry.at(irods::KW_CFG_ADDRESS).get_ref<const std::string&>();
                const auto& mask = access_entry.at(irods::KW_CFG_MASK).get_ref<const std::string&>();

                log_svr::debug("{}: Checking user against host access control entry: user=[{}], group=[{}], "
                               "address=[{}], mask=[{}]",
                               __func__,
                               user,
                               group,
                               addy,
                               mask);

                boost::system::error_code error_code;
                const auto address_entry = ip::make_address_v4(addy, error_code);
                if ( error_code.value() ) {
                    log_svr::debug(
                        "{}: Could not create IPv4 address from address [{}]. Skipping entry.", __func__, addy);
                    continue;
                }

                const auto mask_entry = ip::make_address_v4(mask, error_code);
                if ( error_code.value() ) {
                    log_svr::debug("{}: Could not create IPv4 address from mask [{}]. Skipping entry.", __func__, mask);
                    continue;
                }

                const auto host_client = ip::make_address_v4(_client_host, error_code);
                if ( error_code.value() ) {
                    log_svr::debug("{}: Could not create IPv4 address from _client_host [{}]. Skipping entry.",
                                   __func__,
                                   _client_host);
                    continue;
                }

                bool user_match = false;
                if ( user == _user_name || user == "all" ) {
                    user_match = true;
                }

                const auto matcher = [&group](const std::string& _g) { return group == _g; };
                const auto group_match =
                    ("all" == group || std::any_of(std::begin(group_list), std::end(group_list), matcher));

                if ( group_match || user_match ) {
                    // check if <client, group, clientIP>
                    // match this entry of the control access file.
                    if (((host_client.to_uint() ^ address_entry.to_uint()) & ~mask_entry.to_uint()) == 0) {
                        log_svr::debug("{}: User is allowed to access server.", __func__);
                        return 0;
                    }
                }
            }
            catch ( const boost::bad_any_cast& e ) {
                log_svr::error(ERROR(INVALID_ANY_CAST, e.what()).user_result());
            }
            catch ( const std::out_of_range& e ) {
                log_svr::error(ERROR(KEY_NOT_FOUND, e.what()).user_result());
            }
        }
    }
    catch (const irods::exception& e) {
        log_svr::error(irods::error(e).user_result());
        return e.code(); // NOLINT(bugprone-narrowing-conversions, cppcoreguidelines-narrowing-conversions)
    }

    log_svr::debug("{}: User [{}] does not meet host access control requirements.", __func__, _user_name);
    return CONNECTION_REFUSED;
} // checkHostAccessControl

/**
 * \fn msiCheckHostAccessControl (ruleExecInfo_t *rei)
 *
 * \brief  This microservice sets the access control policy. It checks the
 *  access control by host and user based on the the policy given in the
 *  HostAccessControl file.
 *
 * \module core
 *
 * \since pre-2.1
 *
 * \author Jean-Yves Nief
 *
 * \note  This microservice controls access to the iRODS service
 *  based on the information in the host_access_control information of
 *  server_config.json.
 *
 * \usage See clients/icommands/test/rules/
 *
 * \param[in,out] rei - The RuleExecInfo structure that is automatically
 *    handled by the rule engine. The user does not include rei as a
 *    parameter in the rule invocation.
 *
 * \DolVarDependence none
 * \DolVarModified none
 * \iCatAttrDependence none
 * \iCatAttrModified none
 * \sideeffect none
 *
 * \return integer
 * \retval 0 upon success
 * \pre N/A
 * \post N/A
 * \sa N/A
 **/
int msiCheckHostAccessControl( ruleExecInfo_t *rei ) {
    char group[MAX_NAME_LEN], *hostclient, *result, *username;
    char condstr[MAX_NAME_LEN];
    int i, rc, status;
    genQueryInp_t genQueryInp;
    genQueryOut_t *genQueryOut = NULL;
    rsComm_t *rsComm;

    RE_TEST_MACRO( "    Calling msiCheckHostAccessControl" )
    /* the above line is needed for loop back testing using irule -i option */

    group[0] = '\0';
    rsComm = rei->rsComm;

    /* retrieve user name */
    username = rsComm->clientUser.userName;
    /* retrieve client IP address */
    hostclient = inet_ntoa( rsComm->remoteAddr.sin_addr );
    /* retrieve groups to which the user belong */
    memset( &genQueryInp, 0, sizeof( genQueryInp ) );
    snprintf( condstr, MAX_NAME_LEN, "= '%s'", username );
    addInxVal( &genQueryInp.sqlCondInp, COL_USER_NAME, condstr );
    addInxIval( &genQueryInp.selectInp, COL_USER_GROUP_NAME, 1 );
    genQueryInp.maxRows = MAX_SQL_ROWS;
    status =  rsGenQuery( rsComm, &genQueryInp, &genQueryOut );
    if ( status >= 0 ) {
        for ( i = 0; i < genQueryOut->rowCnt; i++ ) {
            result = genQueryOut->sqlResult[0].value;
            result += i * genQueryOut->sqlResult[0].len;
            strcat( group, result );
            strcat( group, " " );
        }
    }
    else {
        rstrcpy( group, "all", MAX_NAME_LEN );
    }
    clearGenQueryInp( &genQueryInp );
    freeGenQueryOut( &genQueryOut );

    rc = checkHostAccessControl( username, hostclient, group );
    if ( rc < 0 ) {
        rodsLog( LOG_NOTICE, "Access to user %s from host %s has been refused.\n", username, hostclient );
        rei->status = rc;
    }

    return rei->status;

}
