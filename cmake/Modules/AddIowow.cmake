find_package(Iowow)

if(Iowow_FOUND)
  return()
endif()

if("${IOWOW_URL}" STREQUAL "")
  if(EXISTS ${CMAKE_SOURCE_DIR}/iowow.zip)
    set(IOWOW_URL ${CMAKE_SOURCE_DIR}/iowow.zip)
  else()
    set(IOWOW_URL
        https://github.com/Softmotions/iowow/archive/refs/heads/master.zip)
  endif()
endif()

message("IOWOW_URL: ${IOWOW_URL}")

if(APPLE)
  set(BYPRODUCT "${CMAKE_BINARY_DIR}/lib/libiowow-1.a")
else()
  set(BYPRODUCT "${CMAKE_BINARY_DIR}/src/extern_iowow-build/src/libiowow-1.a")
endif()

set(CMAKE_ARGS
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR} -DASAN=${ASAN}
    -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF)

# In order to properly pass owner project CMAKE variables than contains
# semicolons, we used a specific separator for 'ExternalProject_Add', using the
# LIST_SEPARATOR parameter. This allows building fat binaries on macOS, etc.
# (ie: -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64") Otherwise, semicolons get
# replaced with spaces and CMake isn't aware of a multi-arch setup.
set(SSUB "^^")

foreach(
  extra
  CMAKE_OSX_ARCHITECTURES
  CMAKE_C_COMPILER
  CMAKE_TOOLCHAIN_FILE
  ANDROID_PLATFORM
  ANDROID_ABI
  TEST_TOOL_CMD
  PLATFORM
  ENABLE_BITCODE
  ENABLE_ARC
  ENABLE_VISIBILITY
  ENABLE_STRICT_TRY_COMPILE
  ARCHS)
  if(DEFINED ${extra})
    # Replace occurences of ";" with our custom separator and append to
    # CMAKE_ARGS
    string(REPLACE ";" "${SSUB}" extra_sub "${${extra}}")
    list(APPEND CMAKE_ARGS "-D${extra}=${extra_sub}")
  endif()
endforeach()

message("IOWOW CMAKE_ARGS: ${CMAKE_ARGS}")

include(ExternalProject)

ExternalProject_Add(
  extern_iowow
  URL ${IOWOW_URL}
  DOWNLOAD_NAME iowow.zip
  TIMEOUT 360
  PREFIX ${CMAKE_BINARY_DIR}
  BUILD_IN_SOURCE OFF
  UPDATE_COMMAND ""
  UPDATE_DISCONNECTED ${_UPDATE_DISCONNECTED}
  LIST_SEPARATOR "${SSUB}"
  CMAKE_ARGS ${CMAKE_ARGS}
  BUILD_BYPRODUCTS ${BYPRODUCT})

add_library(IOWOW::static STATIC IMPORTED GLOBAL)
set_target_properties(
  IOWOW::static
  PROPERTIES IMPORTED_LINK_INTERFACE_LANGUAGES "C"
             INTERFACE_LINK_LIBRARIES "m"
             IMPORTED_LOCATION ${BYPRODUCT})

add_dependencies(IOWOW::static extern_iowow)

set(IOWOW_LIBRARIES IOWOW::static)
set(IOWOW_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/include)
