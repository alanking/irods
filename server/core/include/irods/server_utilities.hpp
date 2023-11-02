#ifndef IRODS_SERVER_UTILITIES_HPP
#define IRODS_SERVER_UTILITIES_HPP

/// \file

#include "irods/irods_file_object.hpp"

#include <sys/types.h>

#include <string_view>
#include <optional>

struct RsComm;
struct DataObjInp;
struct BytesBuf;

namespace irods
{
    /// The name of the PID file used for the main server.
    ///
    /// \since 4.3.0
    extern const std::string_view PID_FILENAME_MAIN_SERVER;

    /// The name of the PID file used for the delay server.
    ///
    /// \since 4.3.0
    extern const std::string_view PID_FILENAME_DELAY_SERVER;

    /// Checks if the provided rule text contains session variables.
    ///
    /// This function will reject any text that contains a session variable. This includes text
    /// that contains session variables in comments.
    ///
    /// \param[in] _rule_text The rule text to check.
    ///
    /// \return A boolean value.
    /// \retval true  If the rule text contains session variables.
    /// \retval false Otherwise.
    ///
    /// \since 4.2.9
    auto contains_session_variables(const std::string_view _rule_text) -> bool;

    /// Converts provided string to a new BytesBuf structure (caller owns the memory).
    ///
    /// \param[in] _s The string to copy into the buffer.
    ///
    /// \return A pointer to the newly allocated BytesBuf structure.
    ///
    /// \since 4.2.11
    auto to_bytes_buffer(const std::string_view _s) -> BytesBuf*;

    /// Creates a PID file that allows only one instance of a process to run at a time.
    ///
    /// \param[in] _pid_filename The name of the PID file (e.g. "irods.pid").
    ///
    /// \return An integer representing success or failure.
    /// \retval  0 On success.
    /// \retval -1 On failure.
    ///
    /// \since 4.3.0
    auto create_pid_file(const std::string_view _pid_filename) -> int;

    /// Returns the PID stored in the file if available.
    ///
    /// This function will return a \p std::nullopt if the filename does not refer to a file
    /// under the temp directory or the PID is not a child of the calling process.
    ///
    /// \param[in] _pid_filename The name of the file to which contains a PID value (just the
    ///                          filename, not the absolute path).
    ///
    /// \return The PID stored in the file.
    ///
    /// \since 4.3.0
    auto get_pid_from_file(const std::string_view _pid_filename) noexcept -> std::optional<pid_t>;

    /// \brief Returns the resolved resource hierarchy for any object-level overwrite.
    ///
    /// This function is meant primarily for use with \p rsDataObjPut and \p rsDataObjCopy.
    ///
    /// Data object overwrites must conform to a set of rules to be valid:
    ///  - If the data object does not exist, it is not an overwrite.
    ///  - If the data object exists, any targeted resource using e.g. DEST_RESC_NAME_KW must have a replica.
    ///  - The force flag must be present in the input as explicit signal to overwrite the data object.
    ///
    /// \param[in] _comm Server communication object.
    /// \param[in] _inp Input structure for the data object operation.
    /// \param[in] _hier_keyword Which hierarchy keyword to check for (DEST_RESC_HIER_STR_KW or RESC_HIER_STR_KW).
    ///
    /// \return The fully resolved resource hierarchy for the given \p DataObjInp.
    ///
    /// \throws irods::exception If any of the data object overwrite rules listed above is violated.
    ///
    /// \since 4.3.2
    auto get_resource_hierarchy_for_data_object_overwrite(RsComm& _comm,
                                                          DataObjInp& _inp,
                                                          std::string_view _hier_keyword) -> std::string;

    /// \brief Throw if force overwrite of data object to resource with no replica is indicated by the \p DataObjInp.
    ///
    /// The DEST_RESC_NAME_KW is checked as the target/destination resource.
    ///
    /// \param[in] _inp Input structure for the data object operation.
    /// \param[in] _file_obj Object containing data object information.
    ///
    /// \throws irods::exception If all of the following conditions are met: \parblock 
    ///   - The data object exists.
    ///   - \p _inp has FORCE_FLAG_KW in its \p DataObjInp::condInput.
    ///   - No hierarchy under the resource indicated by DEST_RESC_NAME_KW has a replica of the data object.
    ///
    /// If any of these conditions is not met, this function does nothing.
    /// \endparblock
    ///
    /// \since 4.3.2
    auto throw_if_force_overwrite_to_new_resource(const DataObjInp& _inp, const irods::file_object_ptr _file_obj)
        -> void;
} // namespace irods

#endif // IRODS_SERVER_UTILITIES_HPP

