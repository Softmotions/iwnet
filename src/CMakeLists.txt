if(NOT CMAKE_BUILD_TYPE)
  message(
    FATAL_ERROR
      "Please specify the build type -DCMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo"
  )
endif()

find_package(Curl REQUIRED)
find_package(Wslay REQUIRED)
find_package(Bearssl REQUIRED)
find_package(Iowow REQUIRED)

set(MODULES utils poller ssl ws http)

list(APPEND PROJECT_LIBRARIES ${CURL_LIBRARIES} ${WSLAY_LIBRARIES}
     ${BEARSSL_LIBRARIES} ${IOWOW_LIBRARIES})

set(PROJECT_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
list(
  APPEND
  PROJECT_INCLUDE_DIRS
  ${PROJECT_GENERATED_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_BINARY_DIR}/include
  ${CURL_INCLUDE_DIRS}
  ${WSLAY_INCLUDE_DIRS}
  ${BEARSSL_INCLUDE_DIRS}
  ${IOWOW_INCLUDE_DIRS})

if(CMAKE_SIZEOF_VOID_P MATCHES 8)
  add_definitions(-DIW_64)
else()
  add_definitions(-DIW_32)
endif()
add_definitions(-D_GNU_SOURCE)
add_definitions(-D_LARGEFILE_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-DIW_PTHREADS)

file(GLOB ROOT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
list(APPEND ALL_SRC ${ROOT_SRC})

foreach(MODULE IN LISTS MODULES)
  if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/CMakeLists.txt)
    file(GLOB MODULE_SRC ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.c
         ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.cpp)
    file(GLOB MODULE_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.h
         ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE}/*.hpp)
    list(APPEND ALL_SRC ${MODULE_SRC})
    list(APPEND ALL_HDRS ${MODULE_HDRS})
    list(APPEND PUB_HDRS ${MODULE_HDRS})
    list(APPEND PROJECT_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE})
  endif()
endforeach(MODULE)

list(APPEND PUB_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/iwnet.h)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} \
                  -Wall \
                  -Wextra \
                  -Wfatal-errors \
                  -Wno-implicit-fallthrough \
                  -Wno-missing-braces \
                  -Wno-missing-field-initializers \
                  -Wno-shorten-64-to-32 \
                  -Wno-sign-compare \
                  -Wno-unknown-pragmas \
                  -Wno-unused-function \
                  -Wno-unused-parameter \
                  -fPIC \
                  -fsigned-char \
                  -std=gnu11")
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

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

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

add_library(iwnet_s STATIC ${ALL_SRC})
add_dependencies(iwnet_s generated)
target_link_libraries(iwnet_s PUBLIC ${PROJECT_LIBRARIES})
set_target_properties(
  iwnet_s
  PROPERTIES VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}"
             COMPILE_FLAGS "-DIW_STATIC"
             PUBLIC_HEADER "${PUB_HDRS}"
             OUTPUT_NAME iwnet-${PROJECT_VERSION_MAJOR})

set(${PROJECT_NAME}_PUB_HDRS
    ${PUB_HDRS}
    CACHE INTERNAL "${PROJECT_NAME}: Public headers" FORCE)

set(${PROJECT_NAME}_INCLUDE_DIRS
    ${PROJECT_INCLUDE_DIRS}
    CACHE INTERNAL "${PROJECT_NAME}: Include Directories" FORCE)

install(
  TARGETS iwnet_s
  EXPORT iwnet-exports
  FRAMEWORK DESTINATION ${FRAMEWORK_INSTALL_DIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

install(EXPORT iwnet-exports
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME})

install(FILES ${CMAKE_SOURCE_DIR}/LICENSE ${CMAKE_SOURCE_DIR}/Changelog
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(
  FILES ${CMAKE_SOURCE_DIR}/README.md
  RENAME README
  DESTINATION ${CMAKE_INSTALL_DOCDIR})

export(EXPORT iwnet-exports)

message("")
message("CMAKE_GENERATOR: ${CMAKE_GENERATOR}")
message("${PROJECT_NAME} LINK LIBS: ${PROJECT_LIBRARIES}")
message("${PROJECT_NAME} ASAN: ${ASAN}")
message("\n${PROJECT_NAME} INCLUDE DIRS: ${PROJECT_INCLUDE_DIRS}")
message("\n${PROJECT_NAME} SOURCES: ${ALL_SRC}")
message("\n${PROJECT_NAME} PUB_HDRS: ${PUB_HDRS}")
message("\n${PROJECT_NAME} CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message("${PROJECT_NAME} BUILD_TESTS: ${BUILD_TESTS}")
