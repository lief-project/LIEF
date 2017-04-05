cmake_minimum_required(VERSION 3.1)

# Modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/")
include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)
include(Findcppcheck)
include(CppcheckTargets)
include(ExternalProject)

# LIEF version
set(LIEF_VERSION_MAJOR 0)
set(LIEF_VERSION_MINOR 6)
set(LIEF_VERSION_PATCH 1)

project(LIEF VERSION ${LIEF_VERSION_MAJOR}.${LIEF_VERSION_MINOR}.${LIEF_VERSION_PATCH})
message(STATUS "${PROJECT_NAME} ${PROJECT_VERSION}")

# options
option(LIEF_TESTS          "Enable tests"                               OFF)
option(LIEF_DOC            "Enable documentation"                       OFF)
option(LIEF_PYTHON_API     "Enable Python API"                          ON)
option(LIEF_INSTALL_PYTHON "Install Python bindings"                    OFF)
option(LIEF_C_API          "C API"                                      ON)
option(LIEF_EXAMPLES       "Build LIEF C++ examples"                    ON)
option(LIEF_FORCE32        "Force build LIEF 32 bits version"           OFF)
option(LIEF_COVERAGE       "Perform code coverage"                      OFF)
option(LIEF_USE_CCACHE     "Use ccache to speed up compilation"         ON)
option(LIEF_EXTRA_WARNINGS "Enable extra warning from the compiler"     OFF)
option(LIEF_LOGGING        "Enable logging"                             ON)

option(LIEF_ELF            "Build LIEF with ELF module"                 ON)
option(LIEF_PE             "Build LIEF with PE  module"                 ON)
option(LIEF_MACHO          "Build LIEF with MachO module"               ON)

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
find_package(Git REQUIRED)

# Json
# ----
set(LIBJSON_GIT_URL "https://github.com/nlohmann/json.git" CACHE STRING "URL to the JSON lib repo")
ExternalProject_Add(libjson
  GIT_REPOSITORY    ${LIBJSON_GIT_URL}
  GIT_TAG           v2.0.8
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(libjson SOURCE_DIR)
set(LIBJSON_SOURCE_DIR "${SOURCE_DIR}")


# Rang
# ----
set(LIBRANG_GIT_URL "https://github.com/agauniyal/rang.git" CACHE STRING "URL to the Rang lib repo")
ExternalProject_Add(rang_cpp_color
  GIT_REPOSITORY    ${LIBRANG_GIT_URL}
  GIT_TAG           7f2143809b9ac90a1a8a2e779fb357d8709448c2
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(rang_cpp_color SOURCE_DIR)
set(LIBRANG_SOURCE_DIR "${SOURCE_DIR}")


# mbed TLS
# --------
set(MBED_TLS_TAG mbedtls-2.4.0)
set(MBED_TLS_GIT_URL "https://github.com/ARMmbed/mbedtls.git" CACHE STRING "URL to MbedTLS")
set(MBED_TLS_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/mbed_tls")


ExternalProject_Add(mbed_tls
  PREFIX            ${MBED_TLS_PREFIX}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
  GIT_REPOSITORY    ${MBED_TLS_GIT_URL}
  GIT_TAG           ${MBED_TLS_TAG}
  UPDATE_COMMAND    "" # repetitive update are a pain
  BUILD_BYPRODUCTS  ${MBED_TLS_PREFIX})

ExternalProject_get_property(mbed_tls SOURCE_DIR)
set(MBEDTLS_SOURCE_DIR "${SOURCE_DIR}")
set(MBEDTLS_INCLUDE_DIRS "${MBEDTLS_SOURCE_DIR}/include")

set(mbedtls_src_crypto
    "${MBEDTLS_SOURCE_DIR}/library/aes.c"
    "${MBEDTLS_SOURCE_DIR}/library/aesni.c"
    "${MBEDTLS_SOURCE_DIR}/library/arc4.c"
    "${MBEDTLS_SOURCE_DIR}/library/asn1parse.c"
    "${MBEDTLS_SOURCE_DIR}/library/asn1write.c"
    "${MBEDTLS_SOURCE_DIR}/library/base64.c"
    "${MBEDTLS_SOURCE_DIR}/library/bignum.c"
    "${MBEDTLS_SOURCE_DIR}/library/blowfish.c"
    "${MBEDTLS_SOURCE_DIR}/library/camellia.c"
    "${MBEDTLS_SOURCE_DIR}/library/ccm.c"
    "${MBEDTLS_SOURCE_DIR}/library/cipher.c"
    "${MBEDTLS_SOURCE_DIR}/library/cipher_wrap.c"
    "${MBEDTLS_SOURCE_DIR}/library/cmac.c"
    "${MBEDTLS_SOURCE_DIR}/library/ctr_drbg.c"
    "${MBEDTLS_SOURCE_DIR}/library/des.c"
    "${MBEDTLS_SOURCE_DIR}/library/dhm.c"
    "${MBEDTLS_SOURCE_DIR}/library/ecdh.c"
    "${MBEDTLS_SOURCE_DIR}/library/ecdsa.c"
    "${MBEDTLS_SOURCE_DIR}/library/ecjpake.c"
    "${MBEDTLS_SOURCE_DIR}/library/ecp.c"
    "${MBEDTLS_SOURCE_DIR}/library/ecp_curves.c"
    "${MBEDTLS_SOURCE_DIR}/library/entropy.c"
    "${MBEDTLS_SOURCE_DIR}/library/entropy_poll.c"
    "${MBEDTLS_SOURCE_DIR}/library/error.c"
    "${MBEDTLS_SOURCE_DIR}/library/gcm.c"
    "${MBEDTLS_SOURCE_DIR}/library/havege.c"
    "${MBEDTLS_SOURCE_DIR}/library/hmac_drbg.c"
    "${MBEDTLS_SOURCE_DIR}/library/md.c"
    "${MBEDTLS_SOURCE_DIR}/library/md2.c"
    "${MBEDTLS_SOURCE_DIR}/library/md4.c"
    "${MBEDTLS_SOURCE_DIR}/library/md5.c"
    "${MBEDTLS_SOURCE_DIR}/library/md_wrap.c"
    "${MBEDTLS_SOURCE_DIR}/library/memory_buffer_alloc.c"
    "${MBEDTLS_SOURCE_DIR}/library/oid.c"
    "${MBEDTLS_SOURCE_DIR}/library/padlock.c"
    "${MBEDTLS_SOURCE_DIR}/library/pem.c"
    "${MBEDTLS_SOURCE_DIR}/library/pk.c"
    "${MBEDTLS_SOURCE_DIR}/library/pk_wrap.c"
    "${MBEDTLS_SOURCE_DIR}/library/pkcs12.c"
    "${MBEDTLS_SOURCE_DIR}/library/pkcs5.c"
    "${MBEDTLS_SOURCE_DIR}/library/pkparse.c"
    "${MBEDTLS_SOURCE_DIR}/library/pkwrite.c"
    "${MBEDTLS_SOURCE_DIR}/library/platform.c"
    "${MBEDTLS_SOURCE_DIR}/library/ripemd160.c"
    "${MBEDTLS_SOURCE_DIR}/library/rsa.c"
    "${MBEDTLS_SOURCE_DIR}/library/sha1.c"
    "${MBEDTLS_SOURCE_DIR}/library/sha256.c"
    "${MBEDTLS_SOURCE_DIR}/library/sha512.c"
    "${MBEDTLS_SOURCE_DIR}/library/threading.c"
    "${MBEDTLS_SOURCE_DIR}/library/timing.c"
    "${MBEDTLS_SOURCE_DIR}/library/version.c"
    "${MBEDTLS_SOURCE_DIR}/library/version_features.c"
    "${MBEDTLS_SOURCE_DIR}/library/xtea.c"
)

set(mbedtls_src_x509
    "${MBEDTLS_SOURCE_DIR}/library/certs.c"
    "${MBEDTLS_SOURCE_DIR}/library/pkcs11.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_create.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_crl.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_crt.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_csr.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509write_crt.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509write_csr.c"
)

set(mbedtls_src_tls
    "${MBEDTLS_SOURCE_DIR}/library/debug.c"
    "${MBEDTLS_SOURCE_DIR}/library/net_sockets.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_cache.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_ciphersuites.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_cli.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_cookie.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_srv.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_ticket.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls.c"
)


# easyloggingpp
# -------------
set(ELG_GIT_URL "https://github.com/easylogging/easyloggingpp.git" CACHE STRING "URL to the easyloggingpp lib repo")
ExternalProject_Add(easyloggingpp
  GIT_REPOSITORY    ${ELG_GIT_URL}
  #GIT_TAG           "v9.83"
  GIT_TAG           4e9757660072a84b2c76d9230b3c578a3a6f5afb
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(easyloggingpp SOURCE_DIR)
set(ELG_SOURCE_DIR "${SOURCE_DIR}/src")



# LIEF Source definition
# ======================
set_source_files_properties(${mbedtls_src_crypto} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_x509} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_tls} PROPERTIES GENERATED TRUE)
set_source_files_properties(${ELG_SOURCE_DIR}/easylogging++.cc PROPERTIES GENERATED TRUE)

set(LIEF_SRC
  "${ELG_SOURCE_DIR}/easylogging++.cc"
  "${mbedtls_src_crypto}"
  "${mbedtls_src_x509}"
  "${mbedtls_src_tls}"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/logging.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/exception.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/iostream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Visitable.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Visitor.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/BinaryStream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/VectorStream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/elf_json.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/json.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/hash.cpp")

set(LIEF_ABSTRACT_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/Binary.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/Symbol.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/EnumToString.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/Header.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/Section.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Abstract/Parser.cpp")



set(LIBLIEF_SOURCE_FILES
  "${LIEF_SRC}"
  "${LIEF_ABSTRACT_SRC}")

add_library(LIB_LIEF_STATIC STATIC "${LIBLIEF_SOURCE_FILES}") # Static one
add_library(LIB_LIEF_SHARED SHARED "${LIBLIEF_SOURCE_FILES}") # Shared one


if (LIEF_ELF)
  include("${CMAKE_CURRENT_SOURCE_DIR}/src/ELF/CMakeLists.txt")
endif()

if (LIEF_PE)
  include("${CMAKE_CURRENT_SOURCE_DIR}/src/PE/CMakeLists.txt")
endif()

if (LIEF_MACHO)
  include("${CMAKE_CURRENT_SOURCE_DIR}/src/MachO/CMakeLists.txt")
endif()


# LIEF includes
# =============

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/version.h"
)

set (LIEF_PUBLIC_INCLUDE_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}/include/"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/"
  "${CMAKE_CURRENT_BINARY_DIR}/include/"
  "${LIBJSON_SOURCE_DIR}/src/")

set(LIEF_PRIVATE_INCLUDE_DIR
  "${LIEF_PUBLIC_INCLUDE_DIR}"
  "${LIBRANG_SOURCE_DIR}/include"
  "${ELG_SOURCE_DIR}/"
  "${MBEDTLS_INCLUDE_DIRS}")

# Library definition
# ==================
add_definitions(-DELPP_NO_DEFAULT_LOG_FILE)
if (LIEF_ELF)
  add_definitions(-DLIEF_ELF_MODULE)
endif()

if (LIEF_PE)
  add_definitions(-DLIEF_PE_MODULE)
endif()

if (LIEF_MACHO)
  add_definitions(-DLIEF_MACHO_MODULE)
endif()

target_include_directories(LIB_LIEF_STATIC
  PUBLIC  "${LIEF_PUBLIC_INCLUDE_DIR}"
  PRIVATE "${LIEF_PRIVATE_INCLUDE_DIR}")

target_include_directories(LIB_LIEF_SHARED
  PUBLIC  "${LIEF_PUBLIC_INCLUDE_DIR}"
  PRIVATE "${LIEF_PRIVATE_INCLUDE_DIR}")


add_dependencies(LIB_LIEF_STATIC libjson)
add_dependencies(LIB_LIEF_SHARED libjson)

add_dependencies(LIB_LIEF_STATIC easyloggingpp)
add_dependencies(LIB_LIEF_SHARED easyloggingpp)

add_dependencies(LIB_LIEF_STATIC rang_cpp_color)
add_dependencies(LIB_LIEF_SHARED rang_cpp_color)

add_dependencies(LIB_LIEF_STATIC mbed_tls)
add_dependencies(LIB_LIEF_SHARED mbed_tls)

# Flags definition
# ----------------
set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY CXX_STANDARD              11)
set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY CXX_STANDARD_REQUIRED     ON)
set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY POSITION_INDEPENDENT_CODE ON)
#set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY CXX_VISIBILITY_PRESET hidden)


CHECK_CXX_COMPILER_FLAG("-Weverything" HAS_WARN_EVERY)

if (LIEF_EXTRA_WARNINGS AND HAS_WARN_EVERY)
  set(EXTRA_FLAGS
    -Weverything
    -Wno-c++98-compat
    -Wno-c++98-compat-pedantic
    -Wno-padded
    -Wno-unused-exception-parameter
    -Wno-weak-vtables
    -Wno-exit-time-destructors
    -Wno-global-constructors
    -Wno-documentation
    -Wno-documentation-unknown-command
    -Wno-sign-conversion)

  target_compile_options(LIB_LIEF_STATIC PRIVATE ${EXTRA_FLAGS})
  target_compile_options(LIB_LIEF_SHARED PRIVATE ${EXTRA_FLAGS})
endif()

if (MSVC)
  add_definitions(-DNOMINMAX)
  target_compile_options(LIB_LIEF_STATIC PUBLIC /FIiso646.h)
  target_compile_options(LIB_LIEF_SHARED PUBLIC /FIiso646.h)

  target_compile_options(LIB_LIEF_STATIC PUBLIC /MT)

endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  if (UNIX)
    if (LIEF_FORCE32)
      target_compile_options(LIB_LIEF_STATIC PRIVATE -m32)
      target_compile_options(LIB_LIEF_SHARED PRIVATE -m32)

      set_property(TARGET LIB_LIEF_STATIC LIB_LIEF_SHARED PROPERTY LINK_FLAGS -m32)
    endif()

    set(LIB_LIEF_COMPILE_FLAGS
      -Wall -Wextra -Wpedantic
      -Wno-expansion-to-defined
      -fno-stack-protector
      -fomit-frame-pointer -fno-strict-aliasing
      -fexceptions
      -fvisibility=hidden)
    target_compile_options(LIB_LIEF_STATIC PRIVATE ${LIB_LIEF_COMPILE_FLAGS})
    target_compile_options(LIB_LIEF_SHARED PRIVATE ${LIB_LIEF_COMPILE_FLAGS})
  endif()
endif()


if(CROSS_COMPILE_WINDOWS)
  target_link_libraries(LIB_LIEF_STATIC -static -static-libgcc -static-libstdc++)
endif()

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

# Python
# ------

if (LIEF_PYTHON_API)
  if(WIN32)
    set(PYTHON_BUILD_LIEF_DIRECTORY "${CMAKE_BINARY_DIR}/api/python/Release")
  else()
    set(PYTHON_BUILD_LIEF_DIRECTORY "${CMAKE_BINARY_DIR}/api/python")
  endif()
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/api/python")
endif()

# C API
# -----
if(LIEF_C_API)

  # ELF
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/enums.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/enums.h"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/structures.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/structures.h"
    @ONLY
  )

  # PE
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/enums.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/enums.h"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/structures.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/structures.h"
    @ONLY
  )

  # MachO
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/enums.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/enums.h"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/structures.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/structures.h"
    @ONLY
  )

  target_include_directories(LIB_LIEF_STATIC
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include")

  target_include_directories(LIB_LIEF_SHARED
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include")

  include("${CMAKE_CURRENT_SOURCE_DIR}/api/c/CMakeLists.txt")
endif()



# Examples
# ========
if(LIEF_EXAMPLES)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/examples/cpp")

  if (LIEF_C_API)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/examples/c")
  endif()
endif()

# Tests
# =====
if(LIEF_TESTS)
  enable_testing()
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/tests")
  add_custom_target(check-lief COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure)
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

# Package
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/package")





