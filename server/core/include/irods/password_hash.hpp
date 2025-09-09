#ifndef IRODS_PASSWORD_HASH_HPP
#define IRODS_PASSWORD_HASH_HPP

#include <cstdint>
#include <string>

namespace irods
{
    /// \brief Generate a salt for password-based key derivation.
    ///
    /// \param[in] _salt_length Desired length of the salt string. Default: 16 characters.
    ///
    /// \returns String to use as a salt for a KDF.
    ///
    /// \since 5.1.0
    auto generate_salt(std::uint16_t _salt_length = 16) -> std::string;

    /// \brief Cryptographically hash the provided password using the provided salt.
    ///
    /// \param[in] _password The password to hash.
    /// \param[in] _salt The salt to combine with _password for the hash.
    ///
    /// \returns String containing hashed password as a base64-encoded string.
    ///
    /// \since 5.1.0
    auto hash_password(const std::string& _password, const std::string& _salt) -> std::string;
} // namespace irods

#endif // #ifndef IRODS_PASSWORD_HASH_HPP
