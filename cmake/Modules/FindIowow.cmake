mark_as_advanced(IOWOW_INCLUDE_DIRS IOWOW_STATIC_LIB)

find_path(
  IOWOW_INCLUDE_DIRS
  NAMES iowow/iowow.h
  PATH_SUFFIXES ejdb2)

find_library(IOWOW_STATIC_LIB NAMES libiowow-1.a libiowow.a)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Iowow DEFAULT_MSG IOWOW_INCLUDE_DIRS
                                  IOWOW_STATIC_LIB)
