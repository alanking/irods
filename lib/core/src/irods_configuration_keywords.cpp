#include "irods/irods_configuration_keywords.hpp"

namespace irods
{
    // server_config.json keywords
    const char* const KW_CFG_PAM_PASSWORD_LENGTH{"password_length"};
    const char* const KW_CFG_PAM_NO_EXTEND{"no_extend"};
    const char* const KW_CFG_PAM_PASSWORD_MIN_TIME{"password_min_time"};
    const char* const KW_CFG_PAM_PASSWORD_MAX_TIME{"password_max_time"};
    const char* const KW_CFG_PAM_PASSWORD_EXTEND_LIFETIME{"password_extend_lifetime"};

    const char* const KW_CFG_DB_TECHNOLOGY{"technology"};
    const char* const KW_CFG_DB_HOST{"host"};
    const char* const KW_CFG_DB_PORT{"port"};
    const char* const KW_CFG_DB_NAME{"name"};
    const char* const KW_CFG_DB_ODBC_DRIVER{"odbc_driver"};
    const char* const KW_CFG_DB_USERNAME{"username"};
    const char* const KW_CFG_DB_PASSWORD{"password"};
    const char* const KW_CFG_DB_TLSMODE{"tlsmode"};
    const char* const KW_CFG_DB_TLSROOTCERT{"tlsrootcert"};
    const char* const KW_CFG_DB_TLSCERT{"tlscert"};
    const char* const KW_CFG_DB_TLSKEY{"tlskey"};
    const char* const KW_CFG_ZONE_NAME{"zone_name"};
    const char* const KW_CFG_ZONE_KEY{"zone_key"};
    const char* const KW_CFG_NEGOTIATION_KEY{"negotiation_key"};
    const char* const KW_CFG_RE_RULEBASE_SET{"re_rulebase_set"};
    const char* const KW_CFG_RE_NAMESPACE_SET{"rule_engine_namespaces"};
    const char* const KW_CFG_NAMESPACE{"namespace"};
    const char* const KW_CFG_RE_FUNCTION_NAME_MAPPING_SET{"re_function_name_mapping_set"};
    const char* const KW_CFG_RE_DATA_VARIABLE_MAPPING_SET{"re_data_variable_mapping_set"};
    const char* const KW_CFG_RE_PEP_REGEX_SET{"regexes_for_supported_peps"};
    const char* const KW_CFG_DEFAULT_DIR_MODE{"default_dir_mode"};
    const char* const KW_CFG_DEFAULT_FILE_MODE{"default_file_mode"};
    const char* const KW_CFG_DEFAULT_HASH_SCHEME{"default_hash_scheme"};
    const char* const KW_CFG_MATCH_HASH_POLICY{"match_hash_policy"};
    const char* const KW_CFG_FEDERATION{"federation"};
    const char* const KW_CFG_ENVIRONMENT_VARIABLES{"environment_variables"};
    const char* const KW_CFG_ADVANCED_SETTINGS{"advanced_settings"};

    const char* const KW_CFG_SERVER_PORT_RANGE_START{"server_port_range_start"};
    const char* const KW_CFG_SERVER_PORT_RANGE_END{"server_port_range_end"};

    const char* const KW_CFG_LOG_LEVEL{"log_level"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_LEGACY{"legacy"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_SERVER{"server"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_AGENT_FACTORY{"agent_factory"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_AGENT{"agent"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_DELAY_SERVER{"delay_server"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_GENQUERY1{"genquery1"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_GENQUERY2{"genquery2"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_RESOURCE{"resource"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_DATABASE{"database"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_AUTHENTICATION{"authentication"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_API{"api"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_MICROSERVICE{"microservice"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_NETWORK{"network"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_RULE_ENGINE{"rule_engine"};
    const char* const KW_CFG_LOG_LEVEL_CATEGORY_SQL{"sql"};

    const char* const KW_CFG_HOST_ACCESS_CONTROL{"host_access_control"};
    const char* const KW_CFG_ACCESS_ENTRIES{"access_entries"};
    const char* const KW_CFG_USER{"user"};
    const char* const KW_CFG_GROUP{"group"};
    const char* const KW_CFG_MASK{"mask"};

    const char* const KW_CFG_HOST_RESOLUTION{"host_resolution"};
    const char* const KW_CFG_HOST_ENTRIES{"host_entries"};
    const char* const KW_CFG_ADDRESS_TYPE{"address_type"};
    const char* const KW_CFG_ADDRESSES{"addresses"};
    const char* const KW_CFG_ADDRESS{"address"};

    const char* const KW_CFG_HOST{"host"};

    // advanced settings
    const char* const KW_CFG_DELAY_RULE_EXECUTORS{"delay_rule_executors"};
    const char* const KW_CFG_MAX_SIZE_FOR_SINGLE_BUFFER{"maximum_size_for_single_buffer_in_megabytes"};
    const char* const KW_CFG_DEF_NUMBER_TRANSFER_THREADS{"default_number_of_transfer_threads"};
    const char* const KW_CFG_TRANS_CHUNK_SIZE_PARA_TRANS{"transfer_chunk_size_for_parallel_transfer_in_megabytes"};
    const char* const KW_CFG_TRANS_BUFFER_SIZE_FOR_PARA_TRANS{"transfer_buffer_size_for_parallel_transfer_in_megabytes"};
    const char* const KW_CFG_DEF_TEMP_PASSWORD_LIFETIME{"default_temporary_password_lifetime_in_seconds"};
    const char* const KW_CFG_MAX_TEMP_PASSWORD_LIFETIME{"maximum_temporary_password_lifetime_in_seconds"};
    const char* const KW_CFG_NUMBER_OF_CONCURRENT_DELAY_RULE_EXECUTORS{"number_of_concurrent_delay_rule_executors"};
    const char* const KW_CFG_MAX_SIZE_OF_DELAY_QUEUE_IN_BYTES{"maximum_size_of_delay_queue_in_bytes"};
    const char* const KW_CFG_STACKTRACE_FILE_PROCESSOR_SLEEP_TIME_IN_SECONDS{"stacktrace_file_processor_sleep_time_in_seconds"};
    const char* const KW_CFG_MIGRATE_DELAY_SERVER_SLEEP_TIME_IN_SECONDS{"migrate_delay_server_sleep_time_in_seconds"};

    const char* const KW_CFG_RE_CACHE_SALT{"reCacheSalt"};
    const char* const KW_CFG_DELAY_SERVER_SLEEP_TIME_IN_SECONDS{"delay_server_sleep_time_in_seconds"};

    const char* const KW_CFG_DNS_CACHE{"dns_cache"};
    const char* const KW_CFG_HOSTNAME_CACHE{"hostname_cache"};

    const char* const KW_CFG_SHARED_MEMORY_SIZE_IN_BYTES{"shared_memory_size_in_bytes"};
    const char* const KW_CFG_EVICTION_AGE_IN_SECONDS{"eviction_age_in_seconds"};
    const char* const KW_CFG_CACHE_CLEARER_SLEEP_TIME_IN_SECONDS{"cache_clearer_sleep_time_in_seconds"};

    // service_account_environment.json keywords
    const char* const KW_CFG_IRODS_USER_NAME{"irods_user_name"};
    const char* const KW_CFG_IRODS_HOST{"irods_host"};
    const char* const KW_CFG_IRODS_PORT{"irods_port"};
    const char* const KW_CFG_IRODS_HOME{"irods_home"};
    const char* const KW_CFG_IRODS_CWD{"irods_cwd"};
    const char* const KW_CFG_IRODS_AUTHENTICATION_SCHEME{"irods_authentication_scheme"};
    const char* const KW_CFG_IRODS_DEFAULT_RESOURCE{"irods_default_resource"};
    const char* const KW_CFG_IRODS_ZONE{"irods_zone_name"};
    const char* const KW_CFG_IRODS_LOG_LEVEL{"irods_log_level"};
    const char* const KW_CFG_IRODS_AUTHENTICATION_FILE{"irods_authentication_file"};
    const char* const KW_CFG_IRODS_CLIENT_SERVER_POLICY{"irods_client_server_policy"};
    const char* const KW_CFG_IRODS_ENCRYPTION_KEY_SIZE{"irods_encryption_key_size"};
    const char* const KW_CFG_IRODS_ENCRYPTION_SALT_SIZE{"irods_encryption_salt_size"};
    const char* const KW_CFG_IRODS_ENCRYPTION_NUM_HASH_ROUNDS{"irods_encryption_num_hash_rounds"};
    const char* const KW_CFG_IRODS_ENCRYPTION_ALGORITHM{"irods_encryption_algorithm"};
    const char* const KW_CFG_IRODS_DEFAULT_HASH_SCHEME{"irods_default_hash_scheme"};
    const char* const KW_CFG_IRODS_MATCH_HASH_POLICY{"irods_match_hash_policy"};

    const char* const KW_CFG_IRODS_ENVIRONMENT_FILE{"irods_environment_file"};
    const char* const KW_CFG_IRODS_SESSION_ENVIRONMENT_FILE{"irods_session_environment_file"};

    // irods environment advanced settings
    const char* const KW_CFG_IRODS_MAX_SIZE_FOR_SINGLE_BUFFER{"irods_maximum_size_for_single_buffer_in_megabytes"};
    const char* const KW_CFG_IRODS_DEF_NUMBER_TRANSFER_THREADS{"irods_default_number_of_transfer_threads"};
    const char* const KW_CFG_IRODS_MAX_NUMBER_TRANSFER_THREADS{"irods_maximum_number_of_transfer_threads"};
    const char* const KW_CFG_IRODS_TRANS_BUFFER_SIZE_FOR_PARA_TRANS{"irods_transfer_buffer_size_for_parallel_transfer_in_megabytes"};
    const char* const KW_CFG_IRODS_CONNECTION_POOL_REFRESH_TIME{"irods_connection_pool_refresh_time_in_seconds"};

    const char* const KW_CFG_IRODS_TCP_KEEPALIVE_PROBES{"irods_tcp_keepalive_probes"};
    const char* const KW_CFG_IRODS_TCP_KEEPALIVE_TIME_IN_SECONDS{"irods_tcp_keepalive_time_in_seconds"};
    const char* const KW_CFG_IRODS_TCP_KEEPALIVE_INTVL_IN_SECONDS{"irods_tcp_keepalive_intvl_in_seconds"};

    const char* const KW_CFG_TCP_KEEPALIVE_PROBES{"tcp_keepalive_probes"};
    const char* const KW_CFG_TCP_KEEPALIVE_TIME_IN_SECONDS{"tcp_keepalive_time_in_seconds"};
    const char* const KW_CFG_TCP_KEEPALIVE_INTVL_IN_SECONDS{"tcp_keepalive_intvl_in_seconds"};

    // legacy ssl environment variables
    const char* const KW_CFG_IRODS_SSL_CA_CERTIFICATE_PATH{"irods_ssl_ca_certificate_path"};
    const char* const KW_CFG_IRODS_SSL_CA_CERTIFICATE_FILE{"irods_ssl_ca_certificate_file"};
    const char* const KW_CFG_IRODS_SSL_VERIFY_SERVER{"irods_ssl_verify_server"};
    const char* const KW_CFG_IRODS_SSL_CERTIFICATE_CHAIN_FILE{"irods_ssl_certificate_chain_file"};
    const char* const KW_CFG_IRODS_SSL_CERTIFICATE_KEY_FILE{"irods_ssl_certificate_key_file"};
    const char* const KW_CFG_IRODS_SSL_DH_PARAMS_FILE{"irods_ssl_dh_params_file"};

    // irods environment values now included in server_config
    const char* const KW_CFG_CLIENT_SERVER_POLICY{"client_server_policy"};
    const char* const KW_CFG_DEFAULT_RESOURCE_NAME{"default_resource_name"};
    const char* const KW_CFG_ENCRYPTION{"encryption"};
    const char* const KW_CFG_ENCRYPTION_ALGORITHM{"algorithm"};
    const char* const KW_CFG_ENCRYPTION_KEY_SIZE{"key_size"};
    const char* const KW_CFG_ENCRYPTION_NUM_HASH_ROUNDS{"num_hash_rounds"};
    const char* const KW_CFG_ENCRYPTION_SALT_SIZE{"salt_size"};
    const char* const KW_CFG_ZONE_AUTH_SCHEME{"zone_auth_scheme"};
    const char* const KW_CFG_ZONE_PORT{"zone_port"};
    const char* const KW_CFG_ZONE_USER{"zone_user"};

    const char* const KW_CFG_CATALOG_PROVIDER_HOSTS{"catalog_provider_hosts"};
    const char* const KW_CFG_CATALOG_SERVICE_ROLE{"catalog_service_role"};
    const char* const KW_CFG_SERVICE_ROLE_PROVIDER{"provider"};
    const char* const KW_CFG_SERVICE_ROLE_CONSUMER{"consumer"};
    const char* const KW_CFG_SERVICE_ROLE_PROXY{"proxy"};

    const char* const KW_CFG_IRODS_PLUGIN_DIRECTORY{"irods_plugin_directory"};
    const char* const KW_CFG_PLUGIN_DIRECTORY{"plugin_directory"};

    const char* const KW_CFG_PLUGIN_CONFIGURATION{"plugin_configuration"};

    // plugin types
    const char* const KW_CFG_PLUGIN_TYPE_API{"api"};
    const char* const KW_CFG_PLUGIN_TYPE_RULE_ENGINE{"rule_engines"};
    const char* const KW_CFG_PLUGIN_TYPE_AUTHENTICATION{"authentication"};
    const char* const KW_CFG_PLUGIN_TYPE_NETWORK{"network"};
    const char* const KW_CFG_PLUGIN_TYPE_DATABASE{"database"};
    const char* const KW_CFG_PLUGIN_TYPE_RESOURCE{"resources"};
    const char* const KW_CFG_PLUGIN_TYPE_MICROSERVICE{"microservices"};

    const char* const KW_CFG_PLUGIN_SPECIFIC_CONFIGURATION{"plugin_specific_configuration"};
    const char* const KW_CFG_INSTANCE_NAME{"instance_name"};
    const char* const KW_CFG_PLUGIN_NAME{"plugin_name"};

    const char* const KW_CFG_SHARED_MEMORY_INSTANCE{"shared_memory_instance"};
    const char* const KW_CFG_SHARED_MEMORY_MUTEX{"shared_memory_mutex"};

    const char* const KW_CFG_DEFAULT_RULE_ENGINE_PLUGIN_NAME{"re-irods"};
    const char* const KW_CFG_DEFAULT_RULE_ENGINE_INSTANCE_NAME{"default_rule_engine_instance"};

    // access time
    const char* const KW_CFG_ACCESS_TIME{"access_time"};
    const char* const KW_CFG_ACCESS_TIME_QUEUE_NAME_PREFIX{"queue_name_prefix"};
    const char* const KW_CFG_ACCESS_TIME_QUEUE_SIZE{"queue_size"};
    const char* const KW_CFG_ACCESS_TIME_BATCH_SIZE{"batch_size"};
    const char* const KW_CFG_ACCESS_TIME_RESOLUTION_IN_SECONDS{"resolution_in_seconds"};

    // TLS server configurations (inbound traffic)
    const char* const KW_CFG_TLS_SERVER{"tls_server"};
    const char* const KW_CFG_TLS_CERTIFICATE_CHAIN_FILE{"certificate_chain_file"};
    const char* const KW_CFG_TLS_CERTIFICATE_KEY_FILE{"certificate_key_file"};
    const char* const KW_CFG_TLS_DH_PARAMS_FILE{"dh_params_file"};
    // TLS server configurations (outbound traffic)
    const char* const KW_CFG_TLS_CLIENT{"tls_client"};
    const char* const KW_CFG_TLS_CA_CERTIFICATE_FILE{"ca_certificate_file"};
    const char* const KW_CFG_TLS_CA_CERTIFICATE_PATH{"ca_certificate_path"};
    const char* const KW_CFG_TLS_VERIFY_SERVER{"verify_server"};

    const char* const KW_CFG_CONNECTION_POOL_REFRESH_TIME{"connection_pool_refresh_time_in_seconds"};
} // namespace irods

