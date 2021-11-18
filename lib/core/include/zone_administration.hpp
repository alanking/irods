#ifndef IRODS_ZONE_ADMINISTRATION_HPP
#define IRODS_ZONE_ADMINISTRATION_HPP

/// \file

#undef NAMESPACE_IMPL
#undef rxComm

#ifdef IRODS_ZONE_ADMINISTRATION_ENABLE_SERVER_SIDE_API
    #define NAMESPACE_IMPL      server
    #define rxComm              RsComm
    struct RsComm;
#else
    #define NAMESPACE_IMPL      client
    #define rxComm              RcComm
    struct RcComm;
#endif // IRODS_ZONE_ADMINISTRATION_ENABLE_SERVER_SIDE_API

#include "zone.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

/// \since 4.2.11
namespace irods::experimental::administration
{
    /// \since 4.2.11
    ///
    /// A namespace that allows other variations of the library while also making
    /// this interface (and implementation) the default version.
    inline namespace v1
    {
        /// \since 4.2.11
        ///
        /// \brief The generic exception type used by the zone administration library.
        class zone_management_error
            : std::runtime_error
        {
        public:
            using std::runtime_error::runtime_error;
        }; // class zone_management_error
    } // namespace v1

    /// \since 4.2.8
    ///
    /// \brief A namespace defining the set of client-side or server-side API functions.
    ///
    /// This namespace's name changes based on the presence of a special macro. If the following macro
    /// is defined, then the NAMESPACE_IMPL will be \p server, else it will be \p client.
    ///
    ///     - IRODS_ZONE_ADMINISTRATION_ENABLE_SERVER_SIDE_API
    ///
    namespace NAMESPACE_IMPL
    {
        /// \since 4.2.8
        inline namespace v1
        {
            /// \since 4.2.11
            ///
            /// \brief Adds a new zone to the system.
            ///
            /// \throws zone_management_error If the zone type cannot be converted to a string.
            ///
            /// \param[in/out] _comm    The communication object.
            /// \param[in] _name        The zone to add.
            /// \param[in] _host        The host used to connect to the zone.
            /// \param[in] _port        The port used to connect to the zone.
            /// \param[in] _comment     The zone comment.
            /// \param[in] _type        The type of the zone.
            ///
            /// \return An error code.
            auto add_zone(rxComm&                _comm,
                          const std::string_view _name,
                          const std::string_view _host = "",
                          const std::string_view _port = "",
                          const zone_type        _type = zone_type::remote,
                          const std::string_view _comment = "") -> std::error_code;

            /// \since 4.2.11
            ///
            /// \brief Removes a zone from the system.
            ///
            /// \param[in/out] _comm The communication object.
            /// \param[in] _name The zone to remove.
            ///
            /// \return An error code.
            auto remove_zone(rxComm& _comm, const std::string_view _zone) -> std::error_code;

            /// \since 4.2.11
            ///
            /// \brief Changes the name of a zone.
            ///
            /// \param[in/out] _comm The communication object.
            /// \param[in] _name     The zone to update.
            /// \param[in] _new_name The new name of the zone.
            ///
            /// \return An error code.
            auto set_zone_name(rxComm& conn,
                               const std::string_view _name,
                               const std::string_view _new_name) -> std::error_code;

            /// \since 4.2.11
            ///
            /// \brief Changes the connection information of a zone.
            ///
            /// \param[in] _comm          The communication object.
            /// \param[in] _name          The user to update.
            /// \param[in] _host The new type of the user.
            ///
            /// \return An error code.
            auto set_zone_connection_info(rxComm& conn, const user& user, user_type new_user_type) -> std::error_code;

            /// \since 4.2.11
            ///
            /// \brief Set the zone comment.
            ///
            /// \param[in/out] _comm The communication object.
            /// \param[in] _zone The zone to update.
            /// \param[in] _comment The comment to set.
            ///
            /// \return An error code.
            auto set_zone_comment(rxComm& conn, zone& user, std::string_view auth) -> std::error_code;

            /// \since 4.2.11
            ///
            /// \brief Checks if a zone exists.
            ///
            /// \param[in/out] _comm The communication object.
            /// \param[in] _zone The zone to find.
            ///
            /// \return A boolean.
            /// \retval true  If the zone exists.
            /// \retval false Otherwise.
            auto exists(rxComm& _comm, const zone& _zone) -> bool;

            /// \since 4.2.11
            ///
            /// \brief Returns the ID of a zone.
            ///
            /// \param[in/out] _comm The communication object.
            /// \param[in] _zone The zone to find.
            ///
            /// \return A std::optional object containing the ID as a string if the zone exists.
            auto id(rxComm& _comm, const zone& _zone) -> std::optional<std::string>;

            /// \since 4.2.11
            ///
            /// \brief Returns the type of a zone.
            ///
            /// \throws zone_management_error If the value within the catalog cannot be converted
            ///                               to an appropriate zone_type.
            ///
            /// \param[in/out] _comm The communication object.
            /// \param[in] _zone The zone to find.
            ///
            /// \return A std::optional object containing the zone's type if the zone exists.
            auto type(rxComm& _comm, const zone& _zone) -> std::optional<zone_type>;

            /// \since 4.2.11
            ///
            /// \brief Returns the host and port of the zone.
            ///
            /// \param[in/out] _comm The communication object.
            /// \param[in] _zone The zone for which connection info is being requested.
            ///
            /// \return A pair of strings.
            auto connection_info(rxComm& _comm, const zone& _zone) -> std::pair<std::string>;
        } // namespace v1
    } // namespace NAMESPACE_IMPL
} // namespace irods::experimental::administration

#endif // IRODS_ZONE_ADMINISTRATION_HPP
