link_libraries(iwnet_s)

set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(TESTS poller_pipe_test1 poller_proc_test1 poller_scheduler_test1)

add_executable(echo echo.c)

foreach(TN IN ITEMS ${TESTS})
  add_executable(${TN} ${TN}.c)
  set_target_properties(${TN} PROPERTIES COMPILE_FLAGS "-DIW_STATIC -DIW_TESTS")
  add_test(
    NAME ${TN}
    WORKING_DIRECTORY ${TEST_DATA_DIR}
    COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:${TN}>)
endforeach()
