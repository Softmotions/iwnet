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
add_executable(server2 server2.c)
set_target_properties(server1 server2 PROPERTIES COMPILE_FLAGS
                                                 "-DIW_STATIC -DIW_TESTS")
add_test(
  NAME "server1-tests-run.sh"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./server1-tests-run.sh)

add_test(
  NAME "server1-tests-run.sh_valgrind"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./server1-tests-run.sh --valgrind)

add_test(
  NAME "server1-tests-run.sh_ssl"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./server1-tests-run.sh -- --ssl)

add_test(
  NAME "server1-tests-run.sh_valgrind_ssl"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./server1-tests-run.sh --valgrind -- --ssl)

add_test(
  NAME "server2-tests-run.sh"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./server2-tests-run.sh)

add_test(
  NAME "server2-tests-run.sh_ssl"
  WORKING_DIRECTORY ${TEST_DATA_DIR}
  COMMAND sh ./server2-tests-run.sh -- --ssl)

set(TESTS wf_test1)

foreach(TN IN ITEMS ${TESTS})
  add_executable(${TN} ${TN}.c)
  set_target_properties(${TN} PROPERTIES COMPILE_FLAGS "-DIW_STATIC -DIW_TESTS")
  add_test(
    NAME ${TN}
    WORKING_DIRECTORY ${TEST_DATA_DIR}
    COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:${TN}>)
endforeach()
