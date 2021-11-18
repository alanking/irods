#include "zone.hpp"

namespace irods::experimental::administration
{
    inline namespace v1
    {
        zone::zone(std::string                _name,
                   const zone_type            _type,
                   std::optional<std::string> _host,
                   std::optional<std::string> _port,
                   std::optional<std::string> _comment)
            : name{std::move(_name)}
            , type{_type}
            , host{_host ? std::move(*_host) : ""}
            , port{_port ? std::move(*_port) : ""}
            , comment{_comment ? std::move(*_comment) : ""}
        {
        } // zone::zone
    } // namespace v1
} // namespace irods::experimental::administration
