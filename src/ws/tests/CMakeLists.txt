link_libraries(iwnet_s)

set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(TESTS ws_client_test1 ws_client_test2 ws_client_test4)

file(
  COPY .
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
  FILES_MATCHING
  PATTERN "*.pem")

add_executable(ws_server1 ws_server1.c)

foreach(TN IN ITEMS ${TESTS})
  add_executable(${TN} ${TN}.c)
  set_target_properties(${TN} PROPERTIES COMPILE_FLAGS "-DIW_STATIC -DIW_TESTS")
  add_test(
    NAME ${TN}
    WORKING_DIRECTORY ${TEST_DATA_DIR}
    COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:${TN}>)
endforeach()

add_test(
  NAME ws_client_test1_unix_domain_socket
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND ${TEST_TOOL_CMD} ./ws_client_test1 --listen
          socket:///tmp/ws_server1.socket)
