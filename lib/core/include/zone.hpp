# ifndef IRODS_ZONE_ADMINISTRATION_ZONE_HPP
# define IRODS_ZONE_ADMINISTRATION_ZONE_HPP

#include <optional>
#include <string>
#include <string_view>

namespace irods::experimental::administration
{
    inline namespace v1
    {
        /// \since 4.2.8
        ///
        /// \brief Defines the zone types.
        enum class zone_type
        {
            local,  ///< Identifies the zone in which an operation originates.
            remote  ///< Identifies a foreign zone.
        }; // enum class zone_type

#if 0
        struct zone
        {
            explicit zone(std::string                _name,
                          const zone_type            _type = zone_type::remote,
                          std::optional<std::string> _host = std::nullopt,
                          std::optional<std::string> _port = std::nullopt);

            std::string name;
            zone_type   type;
            std::string host;
            std::string port;
            std::string comment;
        }; // zone
#endif
    } // namespace v1
} // namespace irods::experimental::administration

#endif // IRODS_ZONE_ADMINISTRATION_ZONE_HPP
