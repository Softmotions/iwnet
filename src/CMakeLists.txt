if(NOT CMAKE_BUILD_TYPE)
  message(
    FATAL_ERROR
      "Please specify the build type -DCMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo"
  )
endif()

if((CMAKE_BUILD_TYPE EQUAL Release) OR (CMAKE_BUILD_TYPE EQUAL RelWithDebInfo))
  add_definition(-DIW_RELEASE)
endif()

include(CheckIncludeFile)
include(TestBigEndian)
check_include_file("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_file("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file("winsock2.h" HAVE_WINSOCK2_H)
test_big_endian(WORDS_BIGENDIAN)

add_definitions(-DHAVE_CONFIG_H)
add_definitions(-D_FILE_OFFSET_BITS=64)

check_include_file("Block.h" HAVE_BLOCK_H)
if(NOT NOBLOCKS AND CMAKE_C_COMPILER_ID MATCHES "Clang" AND HAVE_BLOCK_H)
  set(IW_BLOCKS ON)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fblocks")
  list(PREPEND PROJECT_LIBRARIES "-lBlocksRuntime")
  add_definitions(-DIW_BLOCKS)
endif()

include(AddIOWOW)

find_package(Threads REQUIRED CMAKE_THREAD_PREFER_PTHREAD)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
                  -Wall \
                  -Wextra \
                  -Wfatal-errors \
                  -Wno-implicit-fallthrough \
                  -Wno-missing-braces \
                  -Wno-missing-field-initializers \
                  -Wno-sign-compare \
                  -Wno-unknown-pragmas \
                  -Wno-unused-function \
                  -Wno-unused-parameter \
                  -std=gnu11 \
                  -fPIC")

if(APPLE)
  set(STRIP_CMD strip -x)
else()
  set(STRIP_CMD ${CMAKE_STRIP} -s)
endif()

if(NOT WIN32) # todo review
  # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
else()
  add_definitions(-D__USE_MINGW_ANSI_STDIO)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pedantic-ms-format")
  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()

if(ASAN)
  set(CMAKE_C_ASAN "-fsanitize=address -fno-omit-frame-pointer")
endif()

set(CMAKE_C_FLAGS_DEBUG
    "${CMAKE_C_ASAN} -O0 -g -ggdb -Werror -DDEBUG -D_DEBUG -UNDEBUG -Wno-unused-variable"
)
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_ASAN} -O3 -DNDEBUG")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,-s")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELEASE} -g")
set(CMAKE_C_FLAGS_RELEASEWITHDEBINFO ${CMAKE_C_FLAGS_RELWITHDEBINFO})
set(PROJECT_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${PROJECT_GENERATED_DIR}/config.h @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/iwnet.h.in
               ${PROJECT_GENERATED_DIR}/iwnet.h @ONLY)

set(MODULES
    bearssl
    wslay
    utils
    poller
    ssl
    ws
    http)

list(APPEND PROJECT_LIBRARIES "IOWOW::static")

list(
  APPEND
  PROJECT_INCLUDE_DIRS
  ${PROJECT_GENERATED_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/bearssl
  ${CMAKE_BINARY_DIR}/include
  ${IOWOW_INCLUDE_DIRS})

file(GLOB ROOT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
list(APPEND ALL_SRC ${ROOT_SRC})

foreach(MODULE IN LISTS MODULES)
  if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/CMakeLists.txt)
    file(GLOB MODULE_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.c
         ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.cc)
    file(GLOB MODULE_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.h
         ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.hh)
    list(APPEND ALL_SRC ${MODULE_SRC})
    list(APPEND ALL_HDRS ${MODULE_HDRS})
    list(APPEND PROJECT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE})
  endif()
endforeach(MODULE)

list(
  APPEND
  PUB_HDRS
  ${PROJECT_GENERATED_DIR}/iwnet.h 
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_mimetypes.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_base64.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_codec.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_pairs.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_utils.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_url.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_curl.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_tests.h
  ${CMAKE_CURRENT_SOURCE_DIR}/utils/iwn_net.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ssl/iwn_brssl_poller_adapter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/poller/iwn_poller.h
  ${CMAKE_CURRENT_SOURCE_DIR}/poller/iwn_proc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/poller/iwn_watcher.h
  ${CMAKE_CURRENT_SOURCE_DIR}/poller/iwn_scheduler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/poller/iwn_poller_adapter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/poller/iwn_direct_poller_adapter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/http/iwn_http_server.h
  ${CMAKE_CURRENT_SOURCE_DIR}/http/iwn_wf.h
  ${CMAKE_CURRENT_SOURCE_DIR}/http/iwn_wf_files.h
  ${CMAKE_CURRENT_SOURCE_DIR}/http/iwn_wf_sst_inmem.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ws/iwn_ws.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ws/iwn_ws_client.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ws/iwn_ws_server.h)

list(REMOVE_DUPLICATES PROJECT_LIBRARIES)
list(REMOVE_DUPLICATES PROJECT_INCLUDE_DIRS)

include_directories(${PROJECT_INCLUDE_DIRS})

foreach(MODULE IN LISTS MODULES)
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/CMakeLists.txt)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE})
  endif()
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tools/CMakeLists.txt)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tools)
  endif()
  if(BUILD_TESTS AND EXISTS
                     ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tests/CMakeLists.txt)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/tests)
  endif()
  if(BUILD_EXAMPLES
     AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/examples/CMakeLists.txt)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/examples)
  endif()
  if(BUILD_BENCHMARKS
     AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/benchmark/CMakeLists.txt)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/benchmark)
  endif()
endforeach(MODULE)

if(NOT BUILD_SHARED_LIBS)
  add_library(iwnet STATIC ${ALL_SRC})
  add_library(iwnet_s ALIAS iwnet)
else()
  add_library(iwnet SHARED ${ALL_SRC})
  add_library(iwnet_s STATIC ${ALL_SRC})
endif()

add_dependencies(iwnet generated)
target_link_libraries(iwnet PUBLIC ${PROJECT_LIBRARIES})

if(BUILD_SHARED_LIBS)
  add_dependencies(iwnet_s generated)
  target_link_libraries(iwnet_s PUBLIC ${PROJECT_LIBRARIES})

  set_target_properties(
    iwnet
    PROPERTIES VERSION ${PROJECT_VERSION}
               SOVERSION ${PROJECT_VERSION_MAJOR}
               PUBLIC_HEADER "${PUB_HDRS}"
               DEFINE_SYMBOL IW_API_EXPORTS)

  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(
      TARGET iwnet
      POST_BUILD
      COMMAND ${STRIP_CMD} $<TARGET_FILE:iwnet>)
  endif()

  set_target_properties(
    iwnet_s
    PROPERTIES VERSION ${PROJECT_VERSION}
               COMPILE_FLAGS "-DIW_STATIC -DIW_NODLL"
               OUTPUT_NAME iwnet-${PROJECT_VERSION_MAJOR})

else()

  set_target_properties(
    iwnet
    PROPERTIES VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}"
               COMPILE_FLAGS "-DIW_STATIC -DIW_NODLL"
               PUBLIC_HEADER "${PUB_HDRS}"
               LINK_FLAGS_RELEASE "${LINK_FLAGS_RELEASE} -s"
               OUTPUT_NAME iwnet-${PROJECT_VERSION_MAJOR})
endif()

if(OWNER_PROJECT_NAME)
  set(IW_PUBLIC_HEADER_DESTINATION
      ${CMAKE_INSTALL_INCLUDEDIR}/${OWNER_PROJECT_NAME}/${PROJECT_NAME})
else()
  set(IW_PUBLIC_HEADER_DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})
endif()

if(DO_INSTALL_CORE)
  include(InstallRequiredSystemLibraries)
  install(
    TARGETS iwnet
    EXPORT iwnet-exports
    FRAMEWORK DESTINATION ${FRAMEWORK_INSTALL_DIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${IW_PUBLIC_HEADER_DESTINATION})
  install(EXPORT iwnet-exports
          DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME})
endif()

if(BUILD_SHARED_LIBS AND DO_INSTALL_CORE)
  install(
    TARGETS iwnet_s
    EXPORT iwnet-static-exports
    FRAMEWORK DESTINATION ${FRAMEWORK_INSTALL_DIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${IW_PUBLIC_HEADER_DESTINATION})
  install(EXPORT iwnet-static-exports
          DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME})
endif()

if(DO_INSTALL_CORE)
  install(FILES ${CMAKE_SOURCE_DIR}/LICENSE ${CMAKE_SOURCE_DIR}/Changelog
          DESTINATION ${CMAKE_INSTALL_DOCDIR})
  install(
    FILES ${CMAKE_SOURCE_DIR}/README.md
    RENAME README
    DESTINATION ${CMAKE_INSTALL_DOCDIR})

  export(EXPORT iwnet-exports)
  if(BUILD_SHARED_LIBS)
    export(EXPORT iwnet-static-exports)
  endif(BUILD_SHARED_LIBS)
endif()

message("")
message("CMAKE_GENERATOR: ${CMAKE_GENERATOR}")
message("${PROJECT_NAME} LINK LIBS: ${PROJECT_LIBRARIES}")
message("${PROJECT_NAME} ASAN: ${ASAN}")
message("\n${PROJECT_NAME} INCLUDE DIRS: ${PROJECT_INCLUDE_DIRS}")
# message("\n${PROJECT_NAME} SOURCES: ${ALL_SRC}")
message("\n${PROJECT_NAME} PUB_HDRS: ${PUB_HDRS}")
message("\n${PROJECT_NAME} CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message("${PROJECT_NAME} BUILD_TESTS: ${BUILD_TESTS}")
message(
  "${PROJECT_NAME} PUBLIC_HEADER_DESTINATION: ${IW_PUBLIC_HEADER_DESTINATION}")
