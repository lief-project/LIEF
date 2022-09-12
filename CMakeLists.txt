cmake_minimum_required(VERSION 3.5)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

set(IS_WIN_CROSS_COMPILE 0)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND CMAKE_CROSSCOMPILING)
  set(IS_WIN_CROSS_COMPILE 1)
endif()


if(WIN32 OR ${IS_WIN_CROSS_COMPILE})
  include(ChooseMSVCCRT)
endif()
include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)
include(ExternalProject)
include(CMakePackageConfigHelpers)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git"
   AND IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  find_package(Git REQUIRED)

  # Information from git
  # ====================
  include(LIEFGit)
else()
  set(LIEF_VERSION_MAJOR "0")
  set(LIEF_VERSION_MINOR "13")
  set(LIEF_VERSION_PATCH "0")
endif()

# LIEF Project
# ============
project(
  LIEF
  VERSION ${LIEF_VERSION_MAJOR}.${LIEF_VERSION_MINOR}.${LIEF_VERSION_PATCH})
message(STATUS "${PROJECT_NAME} ${PROJECT_VERSION}")

# LIEF options
# =============
include(LIEFOptions)

# Compiler detection (C++14, C++17, ...)
include(LIEFCompilerDetection)

# CCACHE
# ======
message(STATUS "Caching: ${LIEF_USE_CCACHE}")
if(LIEF_USE_CCACHE)
  find_program(CCACHE_FOUND ccache)
  if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
    message(STATUS "Found ccache: ${CCACHE_FOUND}")
  else()
    find_program(SCCACHE_FOUND sccache)
    if(SCCACHE_FOUND)
      set(CMAKE_C_COMPILER_LAUNCHER ${SCCACHE_FOUND})
      set(CMAKE_CXX_COMPILER_LAUNCHER ${SCCACHE_FOUND})
      message(STATUS "Found sccache: ${SCCACHE_FOUND}")
    else()
      set(LIEF_USE_CCACHE OFF)
      message(WARNING "Can't find cache solution")
    endif()
  endif()
endif()

# Dependencies
# ============
set(THIRD_PARTY_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/third-party/")
include(LIEFDependencies)

# iOS specific config
# ===================
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED NO)
  set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED NO)
  set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "")
endif()

message(STATUS "CMAKE_CXX_FLAGS_RELEASE:           ${CMAKE_CXX_FLAGS_RELEASE}")
message(STATUS "CMAKE_CXX_FLAGS:                   ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_CXX_LINK_EXECUTABLE:         ${CMAKE_CXX_LINK_EXECUTABLE}")
message(STATUS "CMAKE_CXX_LINK_FLAGS:              ${CMAKE_CXX_LINK_FLAGS}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS:            ${CMAKE_EXE_LINKER_FLAGS}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS_RELEASE:    ${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS:         ${CMAKE_SHARED_LINKER_FLAGS}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS_RELEASE: ${CMAKE_SHARED_LINKER_FLAGS_RELEASE}")
message(STATUS "CMAKE_CXX_LINK_LIBRARY_FILE_FLAG:  ${CMAKE_CXX_LINK_LIBRARY_FILE_FLAG}")
message(STATUS "CMAKE_LINK_LIBRARY_FILE_FLAG:      ${CMAKE_LINK_LIBRARY_FILE_FLAG}")
message(STATUS "CMAKE_LINK_INTERFACE_LIBRARIES:    ${CMAKE_LINK_INTERFACE_LIBRARIES}")
message(STATUS "CMAKE_CXX_IMPLICIT_LINK_LIBRARIES: ${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES}")
message(STATUS "CMAKE_SYSTEM_PROCESSOR:            ${CMAKE_SYSTEM_PROCESSOR}")

# LIEF Source definition
# ======================

set(LIEF_PRIVATE_INCLUDE_DIR)
set(LIEF_PUBLIC_INCLUDE_DIR)

set(LIEF_PUBLIC_INCLUDE_FILES)
set(LIEF_PRIVATE_INCLUDE_FILES)

set(LIBLIEF_SOURCE_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/errors.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/hash_stream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/logging.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/exception.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/iostream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/internal_utils.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/Object.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/Object.tcc"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/Visitor.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/BinaryStream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/VectorStream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/FileStream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/MemoryStream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/SpanStream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/Convert.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/hash.cpp")

# Grouping basic headers together
# ===============================
set(LIEF_INC_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/errors.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/span.hpp"
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
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/utils.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visibility.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Object.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Visitor.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitor_macros.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/BinaryStream.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/VectorStream.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/FileStream.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/MemoryStream.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/SpanStream.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/Convert.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/internal_utils.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/hash_stream.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/frozen.hpp"
)

set(LIEF_VISITOR_INCLUDE_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/hash.hpp")

set(LIEF_INCLUDE_FILES ${LIEF_INC_FILES} ${LIEF_VISITOR_INCLUDE_FILES})

set(LIEF_JSON_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/json.cpp")
set(LIEF_JSON_HDR "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/json.hpp")

list(APPEND LIEF_INC_FILES       "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/json.hpp")
list(APPEND LIBLIEF_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/json_api.cpp")

if(LIEF_ENABLE_JSON)
  list(APPEND LIBLIEF_SOURCE_FILES "${LIEF_JSON_SRC}")
  list(APPEND LIEF_INC_FILES       "${LIEF_JSON_HDR}")
endif()

source_group("Header Files" FILES ${LIEF_INC_FILES})
source_group("Source Files" FILES ${LIBLIEF_SOURCE_FILES})

source_group("Header Files\\visitors" FILES ${LIEF_VISITOR_INCLUDE_FILES})

add_library(LIB_LIEF ${LIBLIEF_SOURCE_FILES} ${LIEF_INCLUDE_FILES})
add_library(LIEF::LIEF ALIAS LIB_LIEF)

if(NOT LIEF_OPT_MBEDTLS_EXTERNAL)
  set_source_files_properties(${mbedtls_src_crypto} PROPERTIES GENERATED TRUE)
  set_source_files_properties(${mbedtls_src_x509} PROPERTIES GENERATED TRUE)
  set_source_files_properties(${mbedtls_src_tls} PROPERTIES GENERATED TRUE)
  target_sources(LIB_LIEF PRIVATE
                 "${mbedtls_src_crypto}"
                 "${mbedtls_src_x509}"
                 "${mbedtls_src_tls}")

  source_group("mbedtls\\crypto" FILES ${mbedtls_src_crypto})
  source_group("mbedtls\\x509" FILES ${mbedtls_src_x509})
  source_group("mbedtls\\tls" FILES ${mbedtls_src_tls})

  target_include_directories(
    LIB_LIEF SYSTEM PRIVATE
      "${MBEDTLS_INCLUDE_DIRS}"
      "${MBEDTLS_SOURCE_DIR}/library"
  )

  add_dependencies(LIB_LIEF lief_mbed_tls)
else()
  find_package(MbedTLS REQUIRED)
  target_link_libraries(LIB_LIEF PRIVATE
                        MbedTLS::mbedcrypto
                        MbedTLS::mbedx509)
endif()

if(WINDOWS AND BUILD_SHARED_LIBS)
  target_link_libraries(LIB_LIEF ws2_32)
endif()

if(MSVC OR ${IS_WIN_CROSS_COMPILE})
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /bigobj")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj")
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug AND WINDOWS)
  add_definitions(-D_ITERATOR_DEBUG_LEVEL=0 -D_SECURE_SCL=0
                  -D_HAS_ITERATOR_DEBUGGING=0)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug AND UNIX)
  target_compile_options(LIB_LIEF PRIVATE -g -O0)
endif()

if(BUILD_SHARED_LIBS OR LIEF_FORCE_API_EXPORTS)
  target_compile_definitions(LIB_LIEF PRIVATE -DLIEF_EXPORTS)
else()
  target_compile_definitions(LIB_LIEF PRIVATE -DLIEF_STATIC)
endif()
if(LIEF_SUPPORT_CXX14)
  target_compile_features(LIB_LIEF PRIVATE cxx_std_14)
endif()

# Abstract part
include("${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/CMakeLists.txt")

# ELF Part
# ========
include("${CMAKE_CURRENT_SOURCE_DIR}/src/ELF/CMakeLists.txt")
if(LIEF_ELF)
  set(ENABLE_ELF_SUPPORT 1)
else()
  set(ENABLE_ELF_SUPPORT 0)
endif()

# PE Part
# =======
include("${CMAKE_CURRENT_SOURCE_DIR}/src/PE/CMakeLists.txt")
if(LIEF_PE)
  set(ENABLE_PE_SUPPORT 1)
else()
  set(ENABLE_PE_SUPPORT 0)
endif()

# MachO part
# ==========
include("${CMAKE_CURRENT_SOURCE_DIR}/src/MachO/CMakeLists.txt")
if(LIEF_MACHO)
  set(ENABLE_MACHO_SUPPORT 1)
else()
  set(ENABLE_MACHO_SUPPORT 0)
endif()

# Logging Configuration
# =====================

target_compile_definitions(LIB_LIEF PRIVATE SPDLOG_DISABLE_DEFAULT_LOGGER
                                            SPDLOG_FUNCTION=)

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  target_compile_definitions(LIB_LIEF PRIVATE SPDLOG_NO_EXCEPTIONS SPDLOG_NO_THREAD_ID)
endif()

# Frozen Configuration
# ====================
if(LIEF_FROZEN_ENABLED)
endif()

# OAT part
# ========
if(LIEF_OAT)
  include(${CMAKE_CURRENT_SOURCE_DIR}/src/OAT/CMakeLists.txt)
  set(ENABLE_OAT_SUPPORT 1)
else()
  set(ENABLE_OAT_SUPPORT 0)
endif()

# DEX part
# ========
if(LIEF_DEX)
  include(${CMAKE_CURRENT_SOURCE_DIR}/src/DEX/CMakeLists.txt)
  set(ENABLE_DEX_SUPPORT 1)
else()
  set(ENABLE_DEX_SUPPORT 0)
endif()

# VDEX part
# =========
if(LIEF_VDEX)
  include(${CMAKE_CURRENT_SOURCE_DIR}/src/VDEX/CMakeLists.txt)
  set(ENABLE_VDEX_SUPPORT 1)
else()
  set(ENABLE_VDEX_SUPPORT 0)
endif()

# ART part
# ========
if(LIEF_ART)
  include(${CMAKE_CURRENT_SOURCE_DIR}/src/ART/CMakeLists.txt)
  set(ENABLE_ART_SUPPORT 1)
else()
  set(ENABLE_ART_SUPPORT 0)
endif()

# Platforms
# =========
include(${CMAKE_CURRENT_SOURCE_DIR}/src/platforms/CMakeLists.txt)

# LIEF includes
# =============
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/version.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/version.h")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/config.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/config.h" @ONLY)

list(APPEND LIEF_PUBLIC_INCLUDE_DIR
     "${CMAKE_CURRENT_SOURCE_DIR}/include/"
     "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/"
     "${CMAKE_CURRENT_BINARY_DIR}/include/")

list(APPEND LIEF_PRIVATE_INCLUDE_DIR "${LIEF_PUBLIC_INCLUDE_DIR}"
     "${CMAKE_CURRENT_SOURCE_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/LIEF.pc.in ${CMAKE_CURRENT_BINARY_DIR}/LIEF.pc
               @ONLY)

target_include_directories(LIB_LIEF
  PUBLIC  "$<BUILD_INTERFACE:${LIEF_PUBLIC_INCLUDE_DIR}>"
  PRIVATE "${LIEF_PRIVATE_INCLUDE_DIR}")

if(LIEF_ENABLE_JSON)
  if(LIEF_OPT_NLOHMANN_JSON_EXTERNAL)
    find_package(nlohmann_json REQUIRED)
    target_link_libraries(LIB_LIEF PRIVATE nlohmann_json::nlohmann_json)
  else()
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/internal/nlohmann/json.hpp
      COMMAND
        ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/internal/nlohmann
      COMMAND
        ${CMAKE_COMMAND} -E copy_directory ${LIBJSON_SOURCE_DIR}/
                                           ${CMAKE_CURRENT_BINARY_DIR}/internal/nlohmann/
      DEPENDS lief_libjson)

    target_sources(LIB_LIEF PRIVATE
                   ${CMAKE_CURRENT_BINARY_DIR}/internal/nlohmann/json.hpp)

    target_include_directories(LIB_LIEF PRIVATE
                               ${CMAKE_CURRENT_BINARY_DIR}/)
  endif()
endif()

if(LIEF_FROZEN_ENABLED)
  if(LIEF_OPT_FROZEN_EXTERNAL)
    find_package(frozen REQUIRED)
    target_link_libraries(LIB_LIEF PRIVATE frozen::frozen)
  else()
    add_dependencies(LIB_LIEF lief_frozen)
    target_include_directories(LIB_LIEF
      PRIVATE "${FROZEN_INCLUDE_DIR}")
  endif()
endif()

# =======================================
# Leaf
# =======================================
if(LIEF_EXTERNAL_LEAF)
  message(STATUS "Using external LEAF version")
  if(LIEF_EXTERNAL_LEAF_DIR)
    message(STATUS "External LEAF include dir: ${LIEF_EXTERNAL_LEAF_DIR}")
    target_include_directories(LIB_LIEF SYSTEM PUBLIC
                               "$<BUILD_INTERFACE:${LIEF_EXTERNAL_LEAF_DIR}>")
  endif()
else()
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/leaf.hpp
    COMMAND
      ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${LEAF_SRC_DIR}/
      ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/
    DEPENDS lief_leaf)

  target_sources(LIB_LIEF PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/leaf.hpp)
endif()

# =======================================
# utfcpp
# =======================================

if(LIEF_OPT_UTFCPP_EXTERNAL)
  find_package(utf8cpp REQUIRED)
  target_link_libraries(LIB_LIEF PRIVATE utf8cpp)
else()
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/internal/utfcpp/utf8.h
    COMMAND
      ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/internal/
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${UTFCPP_INCLUDE_DIR}/
      ${CMAKE_CURRENT_BINARY_DIR}/internal/utfcpp
    DEPENDS lief_utfcpp)

  target_sources(LIB_LIEF PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/internal/utfcpp/utf8.h)
endif()

# =======================================
# tcb/span
# =======================================
if(LIEF_EXTERNAL_SPAN)
  message(STATUS "Using external tcb/span version")
  if(LIEF_EXTERNAL_SPAN_DIR)
    message(STATUS "External span include dir: ${LIEF_EXTERNAL_SPAN_DIR}")
    target_include_directories(LIB_LIEF SYSTEM PUBLIC
                               "$<BUILD_INTERFACE:${LIEF_EXTERNAL_SPAN_DIR}>")
  endif()
else()
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/span.hpp
    COMMAND
      ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${TCB_SPAN_SRC_DIR}/
      ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/
    DEPENDS lief_span)

  target_sources(LIB_LIEF PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/span.hpp)
endif()



target_link_libraries(LIB_LIEF PRIVATE lief_spdlog)

# Flags definition
# ----------------

# cmake-format: off
set_target_properties(
  LIB_LIEF
  PROPERTIES POSITION_INDEPENDENT_CODE ON
             CXX_STANDARD              11
             CXX_STANDARD_REQUIRED     ON
             CXX_VISIBILITY_PRESET     hidden
             C_VISIBILITY_PRESET       hidden)
# cmake-format: on

if(UNIX AND NOT APPLE)
  set_property(
    TARGET LIB_LIEF
    APPEND
    PROPERTY LINK_FLAGS "-Wl,--gc-sections -Wl,--exclude-libs,ALL")
endif()

target_compile_definitions(LIB_LIEF PUBLIC -D_GLIBCXX_USE_CXX11_ABI=1)

# LIEF Sanitizer options
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set(SANITIZER_FLAGS -fno-omit-frame-pointer -g -O1)
if(LIEF_ASAN)
  message(STATUS "Address sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=address)

  set_property(TARGET LIB_LIEF
               APPEND PROPERTY LINK_FLAGS -fsanitize=address)
  target_link_libraries(LIB_LIEF INTERFACE asan)
endif()

if(LIEF_LSAN)
  message(STATUS "Leak sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=leak)

  set_property(TARGET LIB_LIEF
               APPEND PROPERTY LINK_FLAGS -fsanitize=leak)

  target_link_libraries(LIB_LIEF INTERFACE lsan)
endif()

if(LIEF_TSAN)
  message(STATUS "Thread sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=thread)

  set_property(TARGET LIB_LIEF
               APPEND PROPERTY LINK_FLAGS -fsanitize=thread)

  target_link_libraries(LIB_LIEF INTERFACE tsan)
endif()

if(LIEF_USAN)
  message(STATUS "Undefined sanitizer enabled")
  list(APPEND SANITIZER_FLAGS -fsanitize=undefined,null,alignment)

  set_property(TARGET LIB_LIEF
               APPEND PROPERTY LINK_FLAGS -fsanitize=undefined,null,alignment)
  target_link_options(LIB_LIEF PUBLIC -fsanitize=undefined,null,alignment)

  target_link_libraries(LIB_LIEF PUBLIC ubsan -fsanitize=undefined,null,alignment)
endif()

set(LIEF_SANITIZER OFF)
if(LIEF_ASAN OR LIEF_LSAN OR LIEF_TSAN OR LIEF_USAN)
  set(LIEF_SANITIZER ON)
endif()

if(LIEF_SANITIZER)
  message("LIEF Sanitizer enabled: ${SANITIZER_FLAGS}")
  target_compile_options(LIB_LIEF PUBLIC ${SANITIZER_FLAGS})
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/tests/sanitizer")
endif()
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Fuzzing options
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
if(LIEF_FUZZING)
  set(FUZZING_FLAGS -fno-omit-frame-pointer -g -O2 -fsanitize=address,fuzzer-no-link)
  set(FUZZING_LINKER_FLAGS -fsanitize=address,fuzzer-no-link)
  set_property(TARGET LIB_LIEF
               APPEND PROPERTY LINK_FLAGS ${FUZZING_LINKER_FLAGS})

  target_compile_options(LIB_LIEF PRIVATE ${FUZZING_FLAGS})
  target_link_libraries(LIB_LIEF PUBLIC asan pthread)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/fuzzing")
endif()

# Compile Flags
# =============
include(LIEFCompilerFlags)

# Profiling flags
# ---------------
if(LIEF_PROFILING)
  set(PROFILING_FLAGS
      -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc
      -fno-builtin-free -fno-omit-frame-pointer -g)
  target_compile_options(LIB_LIEF PUBLIC ${PROFILING_FLAGS})

  add_executable(elf_profiler profiling/elf_profiler.cpp)
  target_compile_options(elf_profiler PUBLIC ${PROFILING_FLAGS})
  target_link_libraries(elf_profiler PRIVATE LIB_LIEF)

  add_executable(macho_profiler profiling/macho_profiler.cpp)
  target_compile_options(macho_profiler PUBLIC ${PROFILING_FLAGS})
  target_link_libraries(macho_profiler PRIVATE LIB_LIEF)
endif()

# Coverage flags
# --------------
if(LIEF_COVERAGE)
  target_compile_options(LIB_LIEF PRIVATE -g -O0 --coverage -fprofile-arcs
                                          -ftest-coverage)
  target_link_libraries(LIB_LIEF gcov)
endif()

set_target_properties(LIB_LIEF PROPERTIES OUTPUT_NAME LIEF EXPORT_NAME LIEF CLEAN_DIRECT_OUTPUT 1)


# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE
      Release
      CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
                                                       "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "Configuration Types: ${CMAKE_CONFIGURATION_TYPES}")
message(STATUS "Build Types:         ${CMAKE_BUILD_TYPE}")

if(APPLE)
  set_target_properties(LIB_LIEF PROPERTIES MACOSX_RPATH ON)
endif()

# API
# ======================
include(LIEFApi)

# Examples
# ======================
if(LIEF_EXAMPLES)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/examples")
endif()

# Tests
# ======================

if(LIEF_TESTS)
  enable_testing()
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/tests")
endif()

# Documentation
# ======================
if(LIEF_DOC)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/doc)
endif()

# Find Package Config
# ======================
configure_file(
  LIEFConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/LIEFConfig.cmake
  @ONLY)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/LIEFConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion)

# Post-build operations
# ======================
if(BUILD_SHARED_LIBS AND CMAKE_BUILD_TYPE MATCHES "Release")
  if(UNIX AND NOT APPLE)
      add_custom_command(
        TARGET LIB_LIEF
        COMMENT "Strip LIEF shared library"
        POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:LIB_LIEF>
      )
  endif()

  if(APPLE)
    add_custom_command(
      TARGET LIB_LIEF
      COMMENT "Strip LIEF shared library"
      POST_BUILD
      COMMAND ${CMAKE_STRIP} -x -S $<TARGET_FILE:LIB_LIEF>
    )
  endif()
endif()

# Install Prefix
# ======================
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT AND UNIX)
  if(UNIX AND NOT APPLE)
    set(CMAKE_INSTALL_PREFIX
        "/usr"
        CACHE PATH "Install path prefix prepended on to install directories."
              FORCE)
  elseif(APPLE)
    set(CMAKE_INSTALL_PREFIX
        "/usr/local"
        CACHE PATH "" FORCE)
  endif()
endif()

# Installation
# ======================

if(UNIX)
  include(GNUInstallDirs)
  set(CMAKE_INSTALL_LIBDIR "lib")
else()
  if(WIN32)
      set(CMAKE_INSTALL_LIBDIR      "lib")
      set(CMAKE_INSTALL_DATADIR     "share")
      set(CMAKE_INSTALL_INCLUDEDIR  "include")
      set(CMAKE_INSTALL_BINDIR      "bin")
      set(CMAKE_INSTALL_DATAROOTDIR "share")
      message(STATUS "Setting installation destination on Windows to: ${CMAKE_INSTALL_PREFIX}")
    else()
      message(FATAL_ERROR "System not UNIX nor WIN32 - not implemented yet")
    endif()
endif()

install(
  TARGETS LIB_LIEF lief_spdlog
  EXPORT LIEFExport
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
  DIRECTORY ${LIEF_PUBLIC_INCLUDE_DIR}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT headers
  FILES_MATCHING
  REGEX "(.*).(hpp|h|def|inc)$")

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/LIEFConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/LIEFConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/LIEF/cmake
  COMPONENT config)

install(
  FILES       ${CMAKE_CURRENT_BINARY_DIR}/LIEF.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
  COMPONENT   libraries)

if(BUILD_SHARED_LIBS)
  set(lib_type shared)
else()
  set(lib_type static)
endif()

install(
  EXPORT LIEFExport
  NAMESPACE LIEF::
  DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/LIEF/cmake
  FILE LIEFExport-${lib_type}.cmake
  COMPONENT config)

export(
  EXPORT LIEFExport
  NAMESPACE LIEF::
  FILE LIEFExport-${lib_type}.cmake)

# Package
# ======================
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/package")
