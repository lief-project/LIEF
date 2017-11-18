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

execute_process(
  COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE LIEF_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
  COMMAND ${GIT_EXECUTABLE} rev-list --count ${LIEF_COMMIT_HASH}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE LIEF_COMMIT_COUNT
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

execute_process(
  COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE LIEF_GIT_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)


# LIEF version
set(LIEF_VERSION_MAJOR 0)
set(LIEF_VERSION_MINOR 8)
set(LIEF_VERSION_PATCH 3)

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
option(LIEF_ENABLE_JSON    "Enable JSON-related APIs"                   ON)

option(LIEF_ELF            "Build LIEF with ELF module"                 ON)
option(LIEF_PE             "Build LIEF with PE  module"                 ON)
option(LIEF_MACHO          "Build LIEF with MachO module"               ON)

# Sanitizer
option(LIEF_ASAN "Enable Address sanitizer"   OFF)
option(LIEF_LSAN "Enable Leak sanitizer"      OFF)
option(LIEF_TSAN "Enable Thread sanitizer"    OFF)
option(LIEF_USAN "Enable undefined sanitizer" OFF)


# Fuzzer
option(LIEF_FUZZING "Fuzz LIEF" OFF)

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
# Json
# ----
if (LIEF_ENABLE_JSON)
  set(LIBJSON_VERSION 2.1.1)
  set(LIBJSON_SHA256 SHA256=24dff077ec6c02d490d2d2d3d2d03e8566d9a1552d3556bb82fddfdc40c43cdb)
  set(LIBJSON_URL "${THIRD_PARTY_DIRECTORY}/json-${LIBJSON_VERSION}.zip" CACHE STRING "URL to the JSON lib repo")
  ExternalProject_Add(lief_libjson
    URL               ${LIBJSON_URL}
    URL_HASH          ${LIBJSON_SHA256}
    UPDATE_COMMAND    ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   "")

  ExternalProject_get_property(lief_libjson SOURCE_DIR)
  set(LIBJSON_SOURCE_DIR "${SOURCE_DIR}")
  message(STATUS "Enable JSON support")
  set(ENABLE_JSON_SUPPORT 1)
else()
  message(STATUS "Disable JSON support")
  set(ENABLE_JSON_SUPPORT 0)
endif()

# Rang
# ----
set(LIBRANG_VERSION 2.1)
set(LIBRANG_SHA256 SHA256=32e0af3d3d4f628a26e7330d4384a93b16677e5fed57fbdf45ea267c525deba0)
set(LIBRANG_URL     "${THIRD_PARTY_DIRECTORY}/rang-${LIBRANG_VERSION}.zip")
ExternalProject_Add(lief_rang_cpp_color
  URL               ${LIBRANG_URL}
  URL_HASH          ${LIBRANG_SHA256}
  UPDATE_COMMAND    ""
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(lief_rang_cpp_color SOURCE_DIR)
set(LIBRANG_SOURCE_DIR "${SOURCE_DIR}")


# mbed TLS
# --------
set(MBED_TLS_VERSION 2.6.0)
set(MBED_TLS_SHA256 SHA256=695e88deb49373bed2a4dd53ce693066eb079135d59d5f30ec5a7a2603fd26ff)
set(MBED_TLS_URL "${THIRD_PARTY_DIRECTORY}/mbedtls-${MBED_TLS_VERSION}.zip" CACHE STRING "URL to MbedTLS")
set(MBED_TLS_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/mbed_tls")


ExternalProject_Add(lief_mbed_tls
  PREFIX            ${MBED_TLS_PREFIX}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
  URL               ${MBED_TLS_URL}
  URL_HASH          ${MBED_TLS_SHA256}
  UPDATE_COMMAND    "" # repetitive update are a pain
  BUILD_BYPRODUCTS  ${MBED_TLS_PREFIX})

ExternalProject_get_property(lief_mbed_tls SOURCE_DIR)
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
set(ELG_VERSION 9.94.2)
set(ELG_SHA256 SHA256=f99adeb098e28cd6c97ebb7dfe8ddd55bf6b79578aa65b55c34b4b2527f1f235)
set(ELG_URL "${THIRD_PARTY_DIRECTORY}/easyloggingpp-${ELG_VERSION}.zip" CACHE STRING "URL to the easyloggingpp lib repo")
ExternalProject_Add(lief_easyloggingpp
  URL               ${ELG_URL}
  URL_HASH          ${ELG_SHA256}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(lief_easyloggingpp SOURCE_DIR)
set(ELG_SOURCE_DIR "${SOURCE_DIR}/src")

# Fuzzing
# ~~~~~~~
set(FUZZING_FLAGS -fno-omit-frame-pointer -g -O1)
set(FUZZING_LINKER_FLAGS)

list(APPEND FUZZING_FLAGS -fsanitize=address -fsanitize-coverage=trace-pc-guard)
list(APPEND FUZZING_LINKER_FLAGS -fsanitize=address -fsanitize-coverage=trace-pc-guard)

set(LIBFUZZER_SRC_FILES)
if (LIEF_FUZZING)
  message(STATUS "Fuzzing Enabled")

  set(LIBFUZZER_VERSION 8ff5640b48c4c4a3b974daa10a5f445e86ed7428)
  set(LIBFUZZER_SHA256  SHA256=ed067ebc72b993571854edb113e9f3ef74367dfb8bab1a252009aff72e287614)
  set(LIBFUZZER_URL     "${THIRD_PARTY_DIRECTORY}/LibFuzzer-${LIBFUZZER_VERSION}.zip")
  ExternalProject_Add(lief_libfuzzer
  URL               ${LIBFUZZER_URL}
  URL_HASH          ${LIBFUZZER_SHA256}
  CONFIGURE_COMMAND ""
  UPDATE_COMMAND    ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")

  ExternalProject_get_property(lief_libfuzzer SOURCE_DIR)
  set(LIBFUZZER_SOURCE_DIR "${SOURCE_DIR}")

  set(LIBFUZZER_SRC_FILES
    "${LIBFUZZER_SOURCE_DIR}/FuzzerSHA1.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerUtilLinux.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerIO.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerMain.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerShmemWindows.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerUtilWindows.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerUtil.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerExtFunctionsDlsym.cpp"
    #${LIBFUZZER_SOURCE_DIR}/afl/afl_driver.cpp
    "${LIBFUZZER_SOURCE_DIR}/FuzzerShmemPosix.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerUtilDarwin.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerIOWindows.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerExtFunctionsDlsymWin.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerCrossOver.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerDriver.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerExtFunctionsWeak.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerUtilPosix.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerExtFunctionsWeakAlias.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerIOPosix.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerMerge.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerTracePC.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerMutate.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerExtraCounters.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerLoop.cpp"
    "${LIBFUZZER_SOURCE_DIR}/FuzzerClangCounters.cpp"
    )
  list(APPEND LIBLIEF_SOURCE_FILES ${LIBFUZZER_SRC_FILES})

  set_source_files_properties(${LIBFUZZER_SRC_FILES} PROPERTIES GENERATED TRUE)

  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/fuzzing")
endif()


# LIEF Source definition
# ======================
set_source_files_properties(${mbedtls_src_crypto} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_x509} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_tls} PROPERTIES GENERATED TRUE)
set_source_files_properties(${ELG_SOURCE_DIR}/easylogging++.cc PROPERTIES GENERATED TRUE)

set(LIBLIEF_SOURCE_FILES
  "${ELG_SOURCE_DIR}/easylogging++.cc"
  "${mbedtls_src_crypto}"
  "${mbedtls_src_x509}"
  "${mbedtls_src_tls}"
  "${LIBFUZZER_SRC_FILES}"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/logging.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/exception.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/iostream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Visitable.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/Visitor.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/BinaryStream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/BinaryStream/VectorStream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/json.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/hash.cpp")


# Grouping basic headers together
# ===============================
set(LIEF_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Builder.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/exception.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/iostream.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/iterators.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/json.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/LIEF.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/logging.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/MachO.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/to_json.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/types.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/utf8.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visibility.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Visitable.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Visitor.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/BinaryStream.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/BinaryStream/VectorStream.hpp")

set(LIEF_VISITOR_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitors/Hash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitors/json.hpp")


set(LIEF_INCLUDE_FILES
  ${LIEF_INC_FILES}
  ${LIEF_VISITOR_INCLUDE_FILES}
)



source_group("Header Files" FILES ${LIEF_INC_FILES})
source_group("Source Files" FILES ${LIBLIEF_SOURCE_FILES})

source_group("Header Files\\visitors" FILES ${LIEF_VISITOR_INCLUDE_FILES})

add_library(LIB_LIEF_STATIC STATIC ${LIBLIEF_SOURCE_FILES} ${LIEF_INCLUDE_FILES}) # Static one
add_library(LIB_LIEF_SHARED SHARED ${LIBLIEF_SOURCE_FILES} ${LIEF_INCLUDE_FILES}) # Shared one

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


if (LIEF_ELF AND LIEF_ENABLE_JSON)
  target_sources(LIB_LIEF_STATIC PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/elf_json.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitors/elf_json.hpp"
  )

  target_sources(LIB_LIEF_SHARED PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/elf_json.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitors/elf_json.hpp"
  )
endif()


# PE Part
# =======
include("${CMAKE_CURRENT_SOURCE_DIR}/src/PE/CMakeLists.txt")
if (LIEF_PE)
  set(ENABLE_PE_SUPPORT 1)
else()
  set(ENABLE_PE_SUPPORT 0)
endif()

if (LIEF_PE AND LIEF_ENABLE_JSON)
  target_sources(LIB_LIEF_STATIC PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/pe_json.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitors/pe_json.hpp"
  )

  target_sources(LIB_LIEF_SHARED PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/visitors/pe_json.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/visitors/pe_json.hpp"
  )
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
add_definitions(-DELPP_NO_DEFAULT_LOG_FILE)
add_definitions(-DVDEBUG=9)

if (LIEF_LOGGING)
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

set (LIEF_PUBLIC_INCLUDE_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}/include/"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/"
  "${CMAKE_CURRENT_BINARY_DIR}/include/"
  "${LIBJSON_SOURCE_DIR}/")

set(LIEF_PRIVATE_INCLUDE_DIR
  "${LIEF_PUBLIC_INCLUDE_DIR}"
  "${LIBRANG_SOURCE_DIR}/include"
  "${ELG_SOURCE_DIR}/"
  "${MBEDTLS_INCLUDE_DIRS}")

# Grouping external projects
# ==========================
source_group("mbedtls\\crypto" FILES ${mbedtls_src_crypto})
source_group("mbedtls\\x509"   FILES ${mbedtls_src_x509})
source_group("mbedtls\\tls"    FILES ${mbedtls_src_tls})
source_group("easylogging"     FILES ${ELG_SOURCE_DIR}/easylogging++.cc)

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

add_dependencies(LIB_LIEF_STATIC lief_easyloggingpp)
add_dependencies(LIB_LIEF_SHARED lief_easyloggingpp)

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

CHECK_CXX_COMPILER_FLAG("-Weverything" HAS_WARN_EVERY)
CHECK_CXX_COMPILER_FLAG("-Wno-expansion-to-defined" HAS_NO_EXPANSION_TO_DEFINED)

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
      -fno-stack-protector
      -fno-strict-aliasing
      -fomit-frame-pointer
      -fexceptions
      -fvisibility=hidden)


    if (HAS_NO_EXPANSION_TO_DEFINED)
      list(APPEND LIB_LIEF_COMPILE_FLAGS  -Wno-expansion-to-defined)
    endif()
    target_compile_options(LIB_LIEF_STATIC PRIVATE ${LIB_LIEF_COMPILE_FLAGS})
    target_compile_options(LIB_LIEF_SHARED PRIVATE ${LIB_LIEF_COMPILE_FLAGS})
  endif()
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
