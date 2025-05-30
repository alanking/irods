set(IRODS_TEST_TARGET irods_authenticate_client)

set(IRODS_TEST_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/test_authenticate_client.cpp)

set(IRODS_TEST_INCLUDE_PATH ${IRODS_EXTERNALS_FULLPATH_BOOST}/include)

set(IRODS_TEST_LINK_LIBRARIES irods_common
                              irods_client
                              ${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so)
