#ifndef _IRODS_REPL_TYPES_HPP_
#define _IRODS_REPL_TYPES_HPP_

#include "irods_resource_constants.hpp"
#include "irods_object_oper.hpp"
#include "irods_hierarchy_parser.hpp"
#include "irods_plugin_context.hpp"
#include "irods_resource_redirect.hpp"

#include <vector>
#include <list>
#include <map>
#include <string>

// define this so we sort children from highest vote to lowest
struct child_comp {
    bool operator()( float _lhs, float _rhs ) const {
        return _lhs > _rhs;
    }
};
using redirect_map_t = std::multimap<float, irods::hierarchy_parser, child_comp>;

using child_list_t   = std::vector<irods::hierarchy_parser>;
using object_list_t  = std::list<irods::object_oper>;

// define some constants
const std::string CHILD_LIST_PROP{"child_list"};
const std::string OBJECT_LIST_PROP{"object_list"};

#endif // _IRODS_REPL_TYPES_HPP_
