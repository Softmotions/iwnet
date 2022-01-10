link_libraries(iwnet_s)
set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})

file(
  COPY .
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
  FILES_MATCHING
  PATTERN "*.sh"
  PATTERN "*.pem"
  PATTERN "*.log")

add_executable(server1 server1.c)

add_test(
  NAME "http_server1_test"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./tests-run.sh)

add_test(
  NAME "http_server1_valgrind_test"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./tests-run.sh --valgrind)

add_test(
  NAME "https_server1_test"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./tests-run.sh -- --ssl)

add_test(
  NAME "https_server1_valgrind_test"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./tests-run.sh --valgrind -- --ssl)
