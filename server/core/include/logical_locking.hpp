#ifndef IRODS_LOGICAL_LOCKING_HPP
#define IRODS_LOGICAL_LOCKING_HPP

#include <string_view>

struct DataObjInfo;
struct DataObjInp;
struct RsComm;

namespace irods::logical_locking
{
#if 0
    class enum lock
    {
        write,
        read
    };
#endif

    /// \brief Write-lock replica status in RST for all replicas except the opened replica
    ///
    /// \parblock
    /// Updates the replica_state_table with write lock status for all replicas except for
    /// the target replica which is set to the intermediate state.
    /// \endparblock
    ///
    /// \param[in/out] _comm
    /// \param[in] _logical_path
    /// \param[in] _replica_number Replica number of the locked replica
    ///
    /// \since 4.2.9
    auto lock(
        RsComm& _comm,
        const std::string_view _logical_path,
        const int _replica_number) -> void;

    /// \brief Restore replica status in RST for all replicas except the indicated replica
    ///
    /// \parblock
    /// Updates the replica_state_table with the original replica status for all replicas
    /// except for the target replica. The caller is responsible for setting that status.
    /// \endparblock
    ///
    /// \param[in/out] _comm
    /// \param[in] _logical_path
    /// \param[in] _replica_number Replica number of the locked replica
    ///
    /// \since 4.2.9
    auto unlock(
        RsComm& _comm,
        const std::string_view _logical_path,
        const int _replica_number) -> void;
} // namespace irods::logical_locking

#endif // IRODS_LOGICAL_LOCKING_HPP
