cmake_minimum_required(VERSION 3.1)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)
include(Findcppcheck)
include(CppcheckTargets)
include(ExternalProject)

find_package(Git REQUIRED)

# Information from git
# ====================
include(LIEFGit)

# LIEF Project
# ============
project(LIEF VERSION ${LIEF_VERSION_MAJOR}.${LIEF_VERSION_MINOR}.${LIEF_VERSION_PATCH})
message(STATUS "${PROJECT_NAME} ${PROJECT_VERSION}")

# LIEF options
# =============
include(LIEFOptions)

# CCACHE
# ======
find_program(CCACHE_FOUND ccache)
message(STATUS "ccache: ${LIEF_USE_CCACHE}")
if(CCACHE_FOUND AND LIEF_USE_CCACHE)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()


# Dependencies
# ============
set(THIRD_PARTY_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/third-party/")
include(LIEFDependencies)

# LIEF Source definition
# ======================
set_source_files_properties(${mbedtls_src_crypto} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_x509} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_tls} PROPERTIES GENERATED TRUE)

if (LIEF_LOGGING)
  set_source_files_properties(${ELG_SOURCE_DIR}/easylogging++.cc PROPERTIES GENERATED TRUE)
  #set_source_files_properties(${ELG_SOURCE_DIR}/easylogging++.cc PROPERTIES COMPILE_FLAGS -Wno-unused-variable)
  #set_source_files_properties(${ELG_SOURCE_DIR}/easylogging++.h  PROPERTIES COMPILE_FLAGS -Wno-unused-variable)
  set(ELG_CC_PATH "${ELG_SOURCE_DIR}/easylogging++.cc")
endif()

set(LIEF_PRIVATE_INCLUDE_DIR)
set(LIEF_PUBLIC_INCLUDE_DIR)

set(LIEF_PUBLIC_INCLUDE_FILES)
set(LIEF_PRIVATE_INCLUDE_FILES)

set(LIBLIEF_SOURCE_FILES
  "${ELG_CC_PATH}"
  "${mbedtls_src_crypto}"
  "${mbedtls_src_x509}"
  "${mbedtls_src_tls}"
  "${LIBFUZZER_SRC_FILES}"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/logging.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/exception.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/iostream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Object.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Object.tcc"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Visitor.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/BinaryStream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/VectorStream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/hash.cpp")


# Grouping basic headers together
# ===============================
set(LIEF_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Builder.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/exception.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/iostream.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/iterators.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/LIEF.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/logging.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/types.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/utf8.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visibility.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Object.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Visitor.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitor_macros.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/BinaryStream.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/VectorStream.hpp")

set(LIEF_VISITOR_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/hash.hpp")


set(LIEF_INCLUDE_FILES
  ${LIEF_INC_FILES}
  ${LIEF_VISITOR_INCLUDE_FILES}
)

set(LIEF_JSON_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/json.cpp")
set(LIEF_JSON_HDR
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/json.hpp"
  "${LIBJSON_SOURCE_DIR}/json.hpp"
)

if (LIEF_ENABLE_JSON)
  list(APPEND LIBLIEF_SOURCE_FILES     "${LIEF_JSON_SRC}")
  list(APPEND LIEF_INC_FILES           "${LIEF_JSON_HDR}")
  list(APPEND LIEF_PUBLIC_INCLUDE_DIR  "${LIBJSON_SOURCE_DIR}/")
endif()

source_group("Header Files" FILES ${LIEF_INC_FILES})
source_group("Source Files" FILES ${LIBLIEF_SOURCE_FILES})

source_group("Header Files\\visitors" FILES ${LIEF_VISITOR_INCLUDE_FILES})

add_library(LIB_LIEF_STATIC STATIC ${LIBLIEF_SOURCE_FILES} ${LIEF_INCLUDE_FILES}) # Static one
add_library(LIB_LIEF_SHARED SHARED ${LIBLIEF_SOURCE_FILES} ${LIEF_INCLUDE_FILES}) # Shared one

target_compile_definitions(LIB_LIEF_STATIC PRIVATE -DLIEF_STATIC)
target_compile_definitions(LIB_LIEF_SHARED PRIVATE -DLIEF_EXPORTS)

# Abstract part
include("${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/CMakeLists.txt")

# ELF Part
# ========
include("${CMAKE_CURRENT_SOURCE_DIR}/src/ELF/CMakeLists.txt")
if (LIEF_ELF)
  set(ENABLE_ELF_SUPPORT 1)
else()
  set(ENABLE_ELF_SUPPORT 0)
endif()


# PE Part
# =======
include("${CMAKE_CURRENT_SOURCE_DIR}/src/PE/CMakeLists.txt")
if (LIEF_PE)
  set(ENABLE_PE_SUPPORT 1)
else()
  set(ENABLE_PE_SUPPORT 0)
endif()

# MachO part
# ==========
include("${CMAKE_CURRENT_SOURCE_DIR}/src/MachO/CMakeLists.txt")
if (LIEF_MACHO)
  set(ENABLE_MACHO_SUPPORT 1)
else()
  set(ENABLE_MACHO_SUPPORT 0)
endif()


# Logging Configuration
# =====================
if (LIEF_LOGGING)
  add_definitions(-DELPP_NO_DEFAULT_LOG_FILE)
  add_definitions(-DVDEBUG=9)
  set(ENABLE_LOGGING_SUPPORT 1)
else()
  set(ENABLE_LOGGING_SUPPORT 0)
  add_definitions(-DELPP_DISABLE_LOGS)
  add_definitions(-DELPP_NO_LOG_TO_FILE)
  add_definitions(-DELPP_DISABLE_DEFAULT_CRASH_HANDLING)
endif()


# LIEF includes
# =============
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/version.h"
)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/config.h"
  @ONLY
)

list(APPEND LIEF_PUBLIC_INCLUDE_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}/include/"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/"
  "${CMAKE_CURRENT_BINARY_DIR}/include/"
)

list(APPEND LIEF_PRIVATE_INCLUDE_DIR
  "${LIEF_PUBLIC_INCLUDE_DIR}"
  "${LIEF_PUBLIC_INCLUDE_DIR}"
  "${LIBRANG_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${ELG_SOURCE_DIR}"
  "${MBEDTLS_INCLUDE_DIRS}")


# Grouping external projects
# ==========================
source_group("mbedtls\\crypto" FILES ${mbedtls_src_crypto})
source_group("mbedtls\\x509"   FILES ${mbedtls_src_x509})
source_group("mbedtls\\tls"    FILES ${mbedtls_src_tls})
if (LIEF_LOGGING)
source_group("easylogging"     FILES ${ELG_SOURCE_DIR}/easylogging++.cc)
endif()

# Library definition
# ==================
target_include_directories(LIB_LIEF_STATIC
  PUBLIC  "${LIEF_PUBLIC_INCLUDE_DIR}"
  PRIVATE "${LIEF_PRIVATE_INCLUDE_DIR}")

target_include_directories(LIB_LIEF_SHARED
  PUBLIC  "${LIEF_PUBLIC_INCLUDE_DIR}"
  PRIVATE "${LIEF_PRIVATE_INCLUDE_DIR}")


if (LIEF_ENABLE_JSON)
  add_dependencies(LIB_LIEF_STATIC lief_libjson)
  add_dependencies(LIB_LIEF_SHARED lief_libjson)
endif()

if (LIEF_LOGGING)
  add_dependencies(LIB_LIEF_STATIC lief_easyloggingpp)
  add_dependencies(LIB_LIEF_SHARED lief_easyloggingpp)
endif()

add_dependencies(LIB_LIEF_STATIC lief_rang_cpp_color)
add_dependencies(LIB_LIEF_SHARED lief_rang_cpp_color)

add_dependencies(LIB_LIEF_STATIC lief_mbed_tls)
add_dependencies(LIB_LIEF_SHARED lief_mbed_tls)

# Flags definition
# ----------------
set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY CXX_STANDARD              11)
set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY CXX_STANDARD_REQUIRED     ON)
set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY POSITION_INDEPENDENT_CODE ON)


# ASAN - LSAN - TSAN - USAN
# ~~~~~~~~~~~~~~~~~~~~~~~~~
set(SANITIZER_FLAGS -fno-omit-frame-pointer -g -O1)
if (LIEF_ASAN)
  message(STATUS "Address sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=address)

  set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED APPEND PROPERTY LINK_FLAGS -fsanitize=address)
  target_link_libraries(LIB_LIEF_STATIC INTERFACE asan)
  target_link_libraries(LIB_LIEF_SHARED INTERFACE asan)
endif()


if (LIEF_LSAN)
  message(STATUS "Leak sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=leak)

  set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED APPEND PROPERTY LINK_FLAGS -fsanitize=leak)

  target_link_libraries(LIB_LIEF_STATIC INTERFACE lsan)
  target_link_libraries(LIB_LIEF_SHARED INTERFACE lsan)
endif()


if (LIEF_TSAN)
  message(STATUS "Thread sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=thread)

  set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED APPEND PROPERTY LINK_FLAGS -fsanitize=thread)

  target_link_libraries(LIB_LIEF_STATIC INTERFACE tsan)
  target_link_libraries(LIB_LIEF_SHARED INTERFACE tsan)
endif()


if (LIEF_USAN)
  message(STATUS "Undefined sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=undefined)

  set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED APPEND PROPERTY LINK_FLAGS -fsanitize=undefined)

  target_link_libraries(LIB_LIEF_STATIC INTERFACE ubsan)
  target_link_libraries(LIB_LIEF_SHARED INTERFACE ubsan)
endif()

if (LIEF_ASAN OR LIEF_LSAN OR LIEF_TSAN OR LIEF_USAN)
  #message(STATUS "${SANITIZER_FLAGS}")
  target_compile_options(LIB_LIEF_STATIC PRIVATE ${SANITIZER_FLAGS})
  target_compile_options(LIB_LIEF_SHARED PRIVATE ${SANITIZER_FLAGS})
endif()


# Fuzzing
# ~~~~~~~
if (LIEF_FUZZING)
  set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED APPEND PROPERTY LINK_FLAGS ${FUZZING_LINKER_FLAGS})

  target_compile_options(LIB_LIEF_STATIC PRIVATE ${FUZZING_FLAGS})
  target_compile_options(LIB_LIEF_SHARED PRIVATE ${FUZZING_FLAGS})

  target_link_libraries(LIB_LIEF_STATIC asan pthread)
  target_link_libraries(LIB_LIEF_SHARED asan pthread)

  add_dependencies(LIB_LIEF_STATIC lief_libfuzzer)
  add_dependencies(LIB_LIEF_SHARED lief_libfuzzer)
endif()

# Compile Flags
# =============
include(LIEFCompilerFlags)

if(LIEF_COVERAGE)
  target_compile_options(LIB_LIEF_STATIC PRIVATE -g -O0 --coverage -fprofile-arcs -ftest-coverage)
  target_compile_options(LIB_LIEF_SHARED PRIVATE -g -O0 --coverage -fprofile-arcs -ftest-coverage)
  target_link_libraries(LIB_LIEF_STATIC gcov)
  target_link_libraries(LIB_LIEF_SHARED gcov)
endif()

find_package(cppcheck)

set_target_properties(
  LIB_LIEF_STATIC
  PROPERTIES OUTPUT_NAME LIEF
  CLEAN_DIRECT_OUTPUT 1)

set_target_properties(
  LIB_LIEF_SHARED
  PROPERTIES OUTPUT_NAME LIEF
  CLEAN_DIRECT_OUTPUT 1)

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "Configuration Types: ${CMAKE_CONFIGURATION_TYPES}")
message(STATUS "Build Types: ${CMAKE_BUILD_TYPE}")


if(APPLE)
  set_target_properties(LIB_LIEF_STATIC PROPERTIES MACOSX_RPATH ".")
  set_target_properties(LIB_LIEF_SHARED PROPERTIES MACOSX_RPATH ".")
endif()

# API
# ===
include(LIEFApi)


# Examples
# ========
if(LIEF_EXAMPLES)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/examples")
endif()

# Tests
# =====
if(LIEF_TESTS)
  enable_testing()
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/tests")
endif()

# CPP Check
# =========
set(CPPCHECK_TEMPLATE_ARG "[{severity}][{id}] {message} {callstack} \(On {file}:{line}\)")
set(_cppcheck_args "--enable=warning,performance,portability,information")
#add_cppcheck(LIB_LIEF_STATIC FORCE)


# Documentation
# =============
if (LIEF_DOC)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/doc)
endif()


# Install Prefix
# ==============
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT AND UNIX)
  if (UNIX AND NOT APPLE)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install path prefix prepended on to install directories." FORCE)
  elseif (APPLE)
    set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "" FORCE)
  endif()
endif()

# Installation
# ============

install(TARGETS LIB_LIEF_STATIC
  ARCHIVE
  DESTINATION lib
  LIBRARY
  DESTINATION lib
  COMPONENT libraries)

install(TARGETS LIB_LIEF_SHARED
  ARCHIVE
  DESTINATION lib
  LIBRARY
  DESTINATION lib
  COMPONENT libraries)

install(
  DIRECTORY ${LIEF_PUBLIC_INCLUDE_DIR}
  DESTINATION include
  COMPONENT headers
  FILES_MATCHING REGEX "(.*).(hpp|h|def)$")

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/scripts/FindLIEF.cmake
  DESTINATION share/LIEF/cmake
  COMPONENT CMakeScripts
)

# Package
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/package")
