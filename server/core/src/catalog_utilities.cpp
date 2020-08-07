#include "catalog_utilities.hpp"
#include "irods_logger.hpp"
#include "irods_rs_comm_query.hpp"

namespace {
    using log = irods::experimental::log;
} // anonymous namespace

namespace irods::experimental::catalog {

    auto bind_string_to_statement(bind_parameters& _bp) -> void
    {
        const auto& v = _bp.json_input.at(_bp.column_name.data()).get<std::string>();
        _bp.bind_values.push_back(v);

        const auto& value = std::get<std::string>(_bp.bind_values.back());
        log::database::trace("[{}:{}] - binding [{}] to [{}] at [{}]", __FUNCTION__, __LINE__, _bp.column_name, value, _bp.index);

        _bp.statement.bind(_bp.index, value.c_str());
    } // bind_string_to_statement

    auto bind_bigint_to_statement(bind_parameters& _bp) -> void
    {
        const auto v = std::stoul(_bp.json_input.at(_bp.column_name.data()).get<std::string>());
        _bp.bind_values.push_back(v);

        const auto value = std::get<std::uint64_t>(_bp.bind_values.back());
        log::database::trace("[{}:{}] - binding [{}] to [{}] at [{}]", __FUNCTION__, __LINE__, _bp.column_name, value, _bp.index);

        _bp.statement.bind(_bp.index, &value);
    } // bind_bigint_to_statement

    auto bind_integer_to_statement(bind_parameters& _bp) -> void
    {
        const auto v = std::stoi(_bp.json_input.at(_bp.column_name.data()).get<std::string>());
        _bp.bind_values.push_back(v);

        const auto value = std::get<int>(_bp.bind_values.back());
        log::database::trace("[{}:{}] - binding [{}] to [{}] at [{}]", __FUNCTION__, __LINE__, _bp.column_name, value, _bp.index);

        _bp.statement.bind(_bp.index, &value);
    } // bind_integer_to_statement

    auto user_has_permission_to_modify_metadata(rsComm_t& _comm,
                                                nanodbc::connection& _db_conn,
                                                int _object_id,
                                                const entity_type _entity_type) -> bool
    {
        using log = irods::experimental::log;

        switch (_entity_type) {
            case entity_type::data_object:
                [[fallthrough]];
            case entity_type::collection:
            {
                const auto query = fmt::format("select t.token_id from R_TOKN_MAIN t"
                                               " inner join R_OBJT_ACCESS a on t.token_id = a.access_type_id "
                                               "where"
                                               " a.user_id = (select user_id from R_USER_MAIN where user_name = '{}') and"
                                               " a.object_id = '{}'", _comm.clientUser.userName, _object_id);

                if (auto row = execute(_db_conn, query); row.next()) {
                    constexpr int access_modify_object = 1120;
                    return row.get<int>(0) >= access_modify_object;
                }
                break;
            }

            case entity_type::user:
                [[fallthrough]];
            case entity_type::resource:
                return irods::is_privileged_client(_comm);

            default:
                log::database::error("Invalid entity type [entity_type => {}]", _entity_type);
                break;
        }
        return false;
    } // user_has_permission_to_modify_metadata

} // namespace irods::experimental::catalog
