#ifndef IRODS_CATALOG_UTILITIES_HPP
#define IRODS_CATALOG_UTILITIES_HPP

#include "irods_exception.hpp"
#include "rcConnect.h"

#include "json.hpp"
#include "nanodbc/nanodbc.h"

#include <functional>
#include <map>
#include <string>
#include <variant>

namespace irods::experimental::catalog {
    using bind_type = std::variant<std::string, std::uint64_t, int>;

    struct bind_parameters {
        nanodbc::statement& statement;
        const std::size_t index;
        const nlohmann::json& json_input;
        std::string_view column_name;
        std::vector<bind_type>& bind_values;
    };

    using mapping_operator_type = std::function<void(bind_parameters&)>;
    using column_mapping_operator_type = std::map<std::string, mapping_operator_type>;

    auto bind_string_to_statement(bind_parameters& _bp) -> void;
    auto bind_bigint_to_statement(bind_parameters& _bp) -> void;
    auto bind_integer_to_statement(bind_parameters& _bp) -> void;

    namespace data_objects {
        const column_mapping_operator_type column_mapping_operators{
            {"data_id",         bind_bigint_to_statement},
            {"coll_id",         bind_bigint_to_statement},
            {"data_name",       bind_string_to_statement},
            {"data_repl_num",   bind_integer_to_statement},
            {"data_version",    bind_string_to_statement},
            {"data_type_name",  bind_string_to_statement},
            {"data_size",       bind_bigint_to_statement},
            {"data_path",       bind_string_to_statement},
            {"data_owner_name", bind_string_to_statement},
            {"data_owner_zone", bind_string_to_statement},
            {"data_is_dirty",   bind_integer_to_statement},
            {"data_status",     bind_string_to_statement},
            {"data_checksum",   bind_string_to_statement},
            {"data_expiry_ts",  bind_string_to_statement},
            {"data_map_id",     bind_bigint_to_statement},
            {"data_mode",       bind_string_to_statement},
            {"r_comment",       bind_string_to_statement},
            {"create_ts",       bind_string_to_statement},
            {"modify_ts",       bind_string_to_statement},
            {"resc_id",         bind_bigint_to_statement}
        };
    } // namespace data_objects

    enum class entity_type {
        data_object,
        collection,
        user,
        resource,
        zone
    };

    const std::map<std::string, entity_type> entity_type_map{
        {"data_object", entity_type::data_object},
        {"collection", entity_type::collection},
        {"user", entity_type::user},
        {"resource", entity_type::resource},
        {"zone", entity_type::zone}
    };

    auto user_has_permission_to_modify_metadata(rsComm_t& _comm,
                                                nanodbc::connection& _db_conn,
                                                int _object_id,
                                                const entity_type _entity) -> bool;
}

#endif // #ifndef IRODS_CATALOG_UTILITIES_HPP
