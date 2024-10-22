#include "irods/password_hash.hpp"

#include "irods/authenticate.h"
#include "irods/base64.hpp"
#include "irods/irods_at_scope_exit.hpp"
#include "irods/irods_random.hpp"
#include "irods/irods_exception.hpp"
#include "irods/rodsErrorTable.h"
#include "irods/irods_logger.hpp"

#include <fmt/format.h>

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace
{
    using log_server = irods::experimental::log::server;
} // anonymous namespace

namespace irods
{
    auto generate_salt(std::uint16_t _salt_length) -> std::string
    {
        return irods::generate_random_alphanumeric_string(_salt_length);
    } // generate_salt

    auto hash_password(const std::string& _password, const std::string& _salt) -> std::string
    {
        if (_password.empty() || _salt.empty()) {
            THROW(SYS_INVALID_INPUT_PARAM, fmt::format("Cannot derive key from password - password or salt is empty."));
        }
        constexpr size_t maximum_password_length = 50;
        constexpr size_t maximum_salt_length = maximum_password_length;
        if (_password.size() > maximum_password_length || _salt.size() > maximum_salt_length) {
            THROW(PASSWORD_EXCEEDS_MAX_SIZE,
                  fmt::format("Cannot derive key from password - password or salt exceeds maximum size [{}].",
                              maximum_password_length));
        }
        EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "SCRYPT", nullptr);
        EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        const auto free_kdf_ctx = irods::at_scope_exit{[kctx] { EVP_KDF_CTX_free(kctx); }};
        log_server::info("constructing parameters");
        OSSL_PARAM params[6];
        OSSL_PARAM* p = params;
        uint64_t work_factor = 1024;
        uint32_t resources = 8;
        uint32_t parallelization = 16;
        char password_buf[maximum_password_length + 1]{};
        std::strncpy(password_buf, _password.c_str(), _password.size());
        char salt_buf[maximum_salt_length + 1]{};
        std::strncpy(salt_buf, _salt.c_str(), _salt.size());
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, static_cast<void*>(password_buf), static_cast<std::size_t>(_password.size()));
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, static_cast<void*>(salt_buf), static_cast<std::size_t>(_salt.size()));
        *p++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &work_factor);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &resources);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &parallelization);
        *p = OSSL_PARAM_construct_end();
        constexpr int key_len = 64;
        unsigned char hash_buf[key_len + 1]{};
        log_server::info("deriving key");
        if (EVP_KDF_derive(kctx, hash_buf, key_len, params) <= 0) {
            THROW(CAT_PASSWORD_ENCODING_ERROR, fmt::format("{}: Failed to derive key for password.", __func__));
        }
        log_server::info("encoding hash");
        unsigned char out[key_len * 2];
        unsigned long out_len = key_len * 2;
        auto err = base64_encode(hash_buf, key_len, out, &out_len);
        if (err < 0) {
            THROW(err, "base64 encoding of digest failed.");
        }
        log_server::info("Returning encoded hash");
        return std::string{reinterpret_cast<char*>(out), out_len};
    } // hash_password
} // namespace irods
