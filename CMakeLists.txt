cmake_minimum_required(VERSION 3.24)
project(LIEF LANGUAGES C CXX)

enable_language(C)
enable_language(CXX)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()

# Enable https://cmake.org/cmake/help/latest/prop_tgt/MSVC_RUNTIME_LIBRARY.html
cmake_policy(SET CMP0091 NEW)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)
include(ExternalProject)
include(CMakePackageConfigHelpers)

find_package(Git)
if (DEFINED ENV{LIEF_VERSION_ENV})
  string(REGEX MATCHALL "([0-9]+)" VERSION_STRING "$ENV{LIEF_VERSION_ENV}")
  if (NOT VERSION_STRING)
    message(FATAL_ERROR "Invalid version")
  endif()
  list(GET VERSION_STRING 0 LIEF_VERSION_MAJOR)
  list(GET VERSION_STRING 1 LIEF_VERSION_MINOR)
  list(GET VERSION_STRING 2 LIEF_VERSION_PATCH)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git"
       AND IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.git" AND Git_FOUND)
  include(LIEFGit)
else()
  set(LIEF_VERSION_MAJOR "0")
  set(LIEF_VERSION_MINOR "16")
  set(LIEF_VERSION_PATCH "6")
endif()

if (DEFINED ENV{LIEF_COMMIT})
  set(LIEF_COMMIT_HASH "$ENV{LIEF_COMMIT}")
endif()

if (DEFINED ENV{LIEF_BRANCH})
  set(LIEF_GIT_BRANCH "$ENV{LIEF_BRANCH}")
endif()

# LIEF Project
# ============
project(LIEF VERSION
        ${LIEF_VERSION_MAJOR}.${LIEF_VERSION_MINOR}.${LIEF_VERSION_PATCH})
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
message(STATUS "CMAKE_CXX_FLAGS_RELWITHDEBINFO:    ${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
message(STATUS "CMAKE_CXX_FLAGS_DEBUG:             ${CMAKE_CXX_FLAGS_DEBUG}")
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
message(STATUS "CMAKE_MSVC_RUNTIME_LIBRARY:        ${CMAKE_MSVC_RUNTIME_LIBRARY}")

if(LIEF_INSTALL)
  if(UNIX)
    include(GNUInstallDirs)
    set(CMAKE_INSTALL_LIBDIR "lib")
  else()
    set(CMAKE_INSTALL_LIBDIR      "lib")
    set(CMAKE_INSTALL_DATADIR     "share")
    set(CMAKE_INSTALL_INCLUDEDIR  "include")
    set(CMAKE_INSTALL_BINDIR      "bin")
    set(CMAKE_INSTALL_DATAROOTDIR "share")
    message(STATUS "Setting installation destination to: ${CMAKE_INSTALL_PREFIX}")
  endif()
endif()

# LIEF Source definition
# ======================
add_library(LIB_LIEF src/Object.cpp)
add_subdirectory(src)

if(NOT LIEF_PY_LIEF_EXT)
  add_library(LIEF::LIEF ALIAS LIB_LIEF)
endif()

if(NOT LIEF_OPT_MBEDTLS_EXTERNAL)
  set_source_files_properties(${mbedtls_src_files} PROPERTIES GENERATED TRUE)
  target_sources(LIB_LIEF PRIVATE ${mbedtls_src_files})
  target_compile_definitions(LIB_LIEF PRIVATE -DMBEDTLS_NO_PLATFORM_ENTROPY)

  target_include_directories(LIB_LIEF SYSTEM PRIVATE
                             ${MBEDTLS_INCLUDE_DIRS}
                            "${MBEDTLS_SOURCE_DIR}/library"
  )

  add_dependencies(LIB_LIEF lief_mbed_tls)
else()
  find_package(MbedTLS REQUIRED)
  target_link_libraries(LIB_LIEF PRIVATE
                        MbedTLS::mbedcrypto MbedTLS::mbedx509)
endif()

target_compile_definitions(LIB_LIEF PRIVATE
  -DMBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/config/mbedtls/config.h"
)

if(WIN32 AND BUILD_SHARED_LIBS)
  target_link_libraries(LIB_LIEF PRIVATE ws2_32)
endif()

if(MSVC)
  add_compile_options(/bigobj)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug AND UNIX)
  target_compile_options(LIB_LIEF PRIVATE -g -O0)
endif()

if(BUILD_SHARED_LIBS OR LIEF_FORCE_API_EXPORTS)
  target_compile_definitions(LIB_LIEF PRIVATE -DLIEF_EXPORTS)
else()
  target_compile_definitions(LIB_LIEF PRIVATE -DLIEF_STATIC)
endif()


if(LIEF_ENABLE_JSON)
  # Make nlohmann/json is only using C++11 API.
  # Especially, MSVC[14.37.32822] is buggy with (no)rtti & std::any
  # Ref:
  # - https://github.com/nlohmann/json/issues/3900
  # - https://github.com/microsoft/STL/issues/4349#issuecomment-1920093172
  target_compile_definitions(LIB_LIEF PRIVATE JSON_HAS_CPP_11)
endif()

# Logging Configuration
# =====================
target_compile_definitions(LIB_LIEF PRIVATE SPDLOG_DISABLE_DEFAULT_LOGGER
                                            SPDLOG_NO_EXCEPTIONS
                                            SPDLOG_FUNCTION=)

if (MSVC AND NOT CLANG_CL AND NOT LIEF_EXTERNAL_SPDLOG)
  target_compile_definitions(LIB_LIEF PRIVATE FMT_UNICODE=0)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  target_compile_definitions(LIB_LIEF PRIVATE SPDLOG_NO_THREAD_ID)
endif()

# LIEF includes
# =============
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/version.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/version.h")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/config.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/config.h" @ONLY)

set(LIEF_PUBLIC_INCLUDE_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/include/
    ${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/
    ${CMAKE_CURRENT_BINARY_DIR}/include/)

set(LIEF_PRIVATE_INCLUDE_DIR
    ${LIEF_PUBLIC_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/LIEF.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/LIEF.pc @ONLY)

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
  target_compile_definitions(LIB_LIEF PRIVATE JSON_NOEXCEPTION)
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
# Expected
# =======================================
if(LIEF_EXTERNAL_EXPECTED)
  message(STATUS "Using external Expected version")
  find_package(tl-expected REQUIRED)
  target_link_libraries(LIB_LIEF PUBLIC tl::expected)
else()
  add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/expected.hpp
    COMMAND
      ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/
    COMMAND
      ${CMAKE_COMMAND} -E copy_directory ${EXPECTED_SRC_DIR}/include/tl/
      ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/
    DEPENDS lief_expected)

  target_sources(LIB_LIEF PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/internal/expected.hpp)
endif()


# =======================================
# utfcpp
# =======================================

if(LIEF_OPT_UTFCPP_EXTERNAL)
  find_package(utf8cpp REQUIRED)
  target_link_libraries(LIB_LIEF PRIVATE utf8cpp::utf8cpp)
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

if(ANDROID AND LIEF_LOGGING)
  target_link_libraries(LIB_LIEF PUBLIC log)
endif()

# Flags definition
# ----------------
set_target_properties(LIB_LIEF
  PROPERTIES POSITION_INDEPENDENT_CODE ON
             CXX_STANDARD              17
             CXX_STANDARD_REQUIRED     ON
             VISIBILITY_INLINES_HIDDEN ON
             CXX_VISIBILITY_PRESET     hidden
             C_VISIBILITY_PRESET       hidden)

if(UNIX AND NOT APPLE)
  set_property(TARGET LIB_LIEF APPEND
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
  add_subdirectory(tests/sanitizer)
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
  add_subdirectory(fuzzing)
endif()

include(LIEFCompilerFlags)

if(LIEF_PROFILING)
  add_subdirectory(profiling)
endif()

set_target_properties(LIB_LIEF PROPERTIES
                      OUTPUT_NAME LIEF
                      EXPORT_NAME LIEF
                      CLEAN_DIRECT_OUTPUT 1)


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

add_subdirectory(api)

if(LIEF_EXAMPLES)
  add_subdirectory(examples)
endif()

if(LIEF_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(LIEF_DOC)
  add_subdirectory(doc)
endif()


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

# Generate install target and package
# =======================================
if(LIEF_INSTALL)

  # Find Package Config
  # ======================
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/LIEFConfig.cmake.in
                 ${CMAKE_CURRENT_BINARY_DIR}/LIEFConfig.cmake @ONLY)

  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/LIEFConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)

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
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LIEF
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
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LIEF
    FILE LIEFExport-${lib_type}.cmake
    COMPONENT config)

  export(
    EXPORT LIEFExport
    NAMESPACE LIEF::
    FILE LIEFExport-${lib_type}.cmake)

  add_subdirectory(package)
endif()
