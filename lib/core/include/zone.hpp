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
    } // namespace v1
} // namespace irods::experimental::administration

#endif // IRODS_ZONE_ADMINISTRATION_ZONE_HPP
