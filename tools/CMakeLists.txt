set(_TARGETS)

add_executable(strliteral strliteral.c)

list(APPEND _TARGETS "${CMAKE_BINARY_DIR}/include/data_cacert.inc")

add_custom_command(
  OUTPUT "${CMAKE_BINARY_DIR}/include/data_cacert.inc"
  DEPENDS strliteral
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  USES_TERMINAL
  COMMAND cmake -E make_directory ${CMAKE_BINARY_DIR}/include
  COMMAND
    $<TARGET_FILE:strliteral> -i "data_cacert"
    ${CMAKE_SOURCE_DIR}/tools/cacert.pem >
    "${CMAKE_BINARY_DIR}/include/data_cacert.inc")

add_custom_target(generated DEPENDS ${_TARGETS})
