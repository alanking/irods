cmake_minimum_required(VERSION 3.12.0 FATAL_ERROR)

set(plugin_target_part "irods_auth_plugin-pam")
foreach(variant IN ITEMS client server)
  set(plugin_target "${plugin_target_part}_${variant}")

  add_library(
    ${plugin_target}
    MODULE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/auth_check_main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/conversation.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/handshake_session.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/message.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/pam.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/pam_conversation.cpp"
  )

  target_link_libraries(
    ${plugin_target}
    PRIVATE
    irods_common
    irods_plugin_dependencies
    irods_${variant}
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
    "${IRODS_EXTERNALS_FULLPATH_FMT}/lib/libfmt.so"
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    ${CMAKE_DL_LIBS}
  )
  target_include_directories(
    ${plugin_target}
    PRIVATE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/server/api/include>"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
    "${IRODS_EXTERNALS_FULLPATH_FMT}/include"
    "${IRODS_EXTERNALS_FULLPATH_SPDLOG}/include"
  )
  target_compile_definitions(
    ${plugin_target}
    PRIVATE
    ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  )

  install(
    TARGETS
    ${plugin_target}
    LIBRARY
    DESTINATION "${IRODS_PLUGINS_DIRECTORY}/auth"
    COMPONENT ${IRODS_PACKAGE_COMPONENT_RUNTIME_NAME}
  )
endforeach()

target_compile_definitions(
  ${plugin_target_part}_server
  PRIVATE
  RODS_SERVER
  ENABLE_RE
  IRODS_ENABLE_SYSLOG
)
