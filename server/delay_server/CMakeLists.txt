set(
  IRODS_SERVER_DELAYSERVER_SOURCES
  "${CMAKE_CURRENT_SOURCE_DIR}/src/irodsDelayServer.cpp"
)

set(
  IRODS_SERVER_DELAYSERVER_HEADERS_PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include/irods/irodsDelayServer.hpp"
)

add_executable(
  irodsDelayServer
  "${IRODS_SERVER_DELAYSERVER_SOURCES}"
  "${IRODS_SERVER_DELAYSERVER_HEADERS_PUBLIC}"
)
target_link_libraries(
  irodsDelayServer
  PRIVATE
  fmt::fmt
  irods_server
  irods_client
  irods_common
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_program_options.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_container.so"
  rt
  ${CMAKE_DL_LIBS}
  m
)
target_include_directories(
  irodsDelayServer
  PRIVATE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
)
target_compile_definitions(
  irodsDelayServer
  PRIVATE
  ${IRODS_COMPILE_DEFINITIONS_PRIVATE}
  IRODS_ENABLE_SYSLOG
)

add_dependencies(all-server irodsDelayServer)
install(
  TARGETS
  irodsDelayServer
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_SBINDIR}"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_SERVER_NAME}
)

install(
  FILES ${IRODS_SERVER_DELAYSERVER_HEADERS_PUBLIC}
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/irods"
  COMPONENT ${IRODS_PACKAGE_COMPONENT_DEVELOPMENT_NAME}
)
