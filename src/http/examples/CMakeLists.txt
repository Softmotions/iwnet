link_libraries(iwnet_s)

file(
  COPY .
  DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
  FILES_MATCHING
  PATTERN "*.pem")

add_executable(echo_http_server echo_http_server.c)
