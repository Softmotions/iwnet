link_libraries(iwnet_s)
set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})

file(
  COPY .
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
  FILES_MATCHING
  PATTERN "*.sh"
  PATTERN "*.log")

add_executable(server1 server1.c)

add_test(
  NAME "http_server1"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./tests-run.sh)

