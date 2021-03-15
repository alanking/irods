#ifndef IRODS_LOGICAL_LOCKING_HPP
#define IRODS_LOGICAL_LOCKING_HPP

#include <string_view>

struct RsComm;

namespace irods::logical_locking
{
    // data_status column will contain something like the following when an object is locked for every replica:
    //{
    //    "original_status": 1,
    //    "agents": [
    //        {
    //            "hostname": <string>,
    //            "pid": <uint32>,
    //            "timestamp": <rodsLong>
    //        },
    //        ...
    //    ]
    //}
    //

    static inline constexpr int restore_status = -1;

    enum class lock_type
    {
        read,
        write
    };

    auto get_original_replica_status(
        const std::uint64_t _data_id,
        const int           _replica_number) -> int;

    auto lock(
        const std::uint64_t _data_id,
        const int           _replica_number,
        const lock_type     _lock_type) -> int;

    auto unlock(
        const std::uint64_t _data_id,
        const int           _replica_number,
        const int           _replica_status,
        const int           _other_replica_statuses = restore_status) -> int;

    auto lock_and_publish(
        RsComm&             _comm,
        const std::uint64_t _data_id,
        const int           _replica_number,
        const lock_type     _lock_type) -> int;

    auto unlock_and_publish(
        RsComm&             _comm,
        const std::uint64_t _data_id,
        const int           _replica_number,
        const int           _replica_status,
        const int           _other_replica_statuses = restore_status) -> int;
} // namespace irods::logical_locking

#endif // #ifndef IRODS_LOGICAL_LOCKING_HPP
