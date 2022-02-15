mark_as_advanced(WSLAY_INCLUDE_DIRS WSLAY_STATIC_LIB)

find_path(WSLAY_INCLUDE_DIRS NAMES wslay/wslay.h)
find_library(WSLAY_STATIC_LIB NAMES libwslay.a)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Wslay DEFAULT_MSG WSLAY_INCLUDE_DIRS
                                  WSLAY_STATIC_LIB)

if(Wslay_FOUND)
  set(WSLAY_LIBRARIES ${WSLAY_STATIC_LIB})
endif()
