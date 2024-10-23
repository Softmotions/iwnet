cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

cmake_policy(SET CMP0135 NEW)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
                      "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

include(CMakeToolsHelpers OPTIONAL)
set(DEB_CHANGELOG_REQUIRED ON)
set(DEB_CHANGELOG "${CMAKE_CURRENT_SOURCE_DIR}/Changelog")
unset(CHANGELOG_LAST_VERSION)
unset(CHANGELOG_LAST_MESSAGE)

include(DebChangelog)
include(GitRevision)

set(PROJECT_MAINTAINER "Anton Adamansky <adamansky@softmotions.com>")
project(
  iwnet
  VERSION
    ${CHANGELOG_LAST_VERSION_MAJOR}.${CHANGELOG_LAST_VERSION_MINOR}.${CHANGELOG_LAST_VERSION_PATCH}
  DESCRIPTION
    "Asynchronous HTTP framework with support of websockets client/server, SSL and routing"
  HOMEPAGE_URL https://github.com/Softmotions/iwnet
  LANGUAGES C)

set(CMAKE_C_VISIBILITY_PRESET hidden)

include(GNUInstallDirs)
include(ProjectUtils)

option(BUILD_TESTS "Build test cases" OFF)
option(ASAN "Turn on address sanitizer" OFF)
option(NOBLOCKS "Turn off Clang Blocks support" OFF)

macro_ensure_out_of_source_build(
  "${CMAKE_PROJECT_NAME} requires an out of source build.")

if(BUILD_TESTS)
  include(CTest)
  enable_testing()
  add_definitions(-DIW_TESTS)
endif(BUILD_TESTS)

if(NOT CPACK_GENERATORS)
  set(DO_INSTALL_CORE ON)
endif()

add_subdirectory(tools)
add_subdirectory(src)

message("${PROJECT_NAME} GIT_REVISION: ${GIT_REVISION}")
message("${PROJECT_NAME} CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message("${PROJECT_NAME} CMAKE_GENERATOR: ${CMAKE_GENERATOR}")
if(MXE_HOME)
  message("${PROJECT_NAME} MXE_HOME: ${MXE_HOME}")
endif()
if(CMAKE_SYSTEM_NAME)
  message("${PROJECT_NAME} CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
endif()
message("${PROJECT_NAME} PROJECT: ${CHANGELOG_LAST_LINE}")
if(CHANGELOG_MESSAGE)
  message("${PROJECT_NAME} CHANGELOG_MESSAGE:\n  ${CHANGELOG_MESSAGE}")
endif()
