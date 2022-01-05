link_libraries(iwnet_s)

set(TEST_DATA_DIR ${CMAKE_CURRENT_BINARY_DIR})
#set(TESTS http_test1)

file(
  COPY .
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
  FILES_MATCHING
  PATTERN "*.js"
  PATTERN "*.pem"
  PATTERN "*.lock"
  PATTERN "*.json")

#add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/node_modules
#                   COMMAND yarn --non-interactive --no-progress install)
#add_custom_target(http_tests DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/node_modules)

add_executable(server1 server1.c)

foreach(TN IN ITEMS ${TESTS})
  add_executable(${TN} ${TN}.c)
  #add_dependencies(${TN} http_tests)
  set_target_properties(${TN} PROPERTIES COMPILE_FLAGS "-DIW_STATIC -DIW_TEST")
  add_test(
    NAME ${TN}
    WORKING_DIRECTORY ${TEST_DATA_DIR}
    COMMAND ${TEST_TOOL_CMD} $<TARGET_FILE:${TN}>)
endforeach()
