#ifndef IRODS_FINALIZE_UTILITIES_HPP
#define IRODS_FINALIZE_UTILITIES_HPP

#include "rodsType.h"

#include <string_view>

struct RsComm;
struct DataObjInfo;
struct DataObjInp;
struct l1desc;

namespace irods
{
    auto apply_acl_from_cond_input(RsComm& _comm, const DataObjInp& _inp) -> void;

    auto apply_metadata_from_cond_input(RsComm& _comm, const DataObjInp& _inp) -> void;

    auto register_new_checksum(RsComm& _comm, DataObjInfo& _info, std::string_view _original_checksum) -> std::string;

    auto verify_checksum(RsComm& _comm, DataObjInfo& _info, std::string_view _original_checksum) -> std::string;

    auto get_size_in_vault(RsComm& _comm, DataObjInfo& _info, const bool _verify_size, const rodsLong_t _recorded_size) -> rodsLong_t;

    auto purge_cache(RsComm& _comm, DataObjInfo& _info) -> int;

    auto duplicate_l1_descriptor(const l1desc& _src) -> l1desc;
} // namespace irods

#endif // IRODS_FINALIZE_UTILITIES_HPP
