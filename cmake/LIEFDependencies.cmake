if(__add_lief_dependencies)
	return()
endif()
set(__add_lief_dependencies ON)

# Json
# ----
if (LIEF_ENABLE_JSON)
  set(LIBJSON_VERSION 3.7.3)
  set(LIBJSON_SHA256 SHA256=e46d26550e8cafc7d7d2564fdf09d20bd14a72c417396bf7ca815b94894d1631)
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
set(MBED_TLS_VERSION 2.23.0)
set(MBED_TLS_SHA256 SHA256=bbf9c3cc6b7603f2f15bbba7badcf6cf188a9d5aaa63c4df2d61213f459c2f5f)
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
  "${MBEDTLS_SOURCE_DIR}/library/aria.c"
  "${MBEDTLS_SOURCE_DIR}/library/asn1parse.c"
  "${MBEDTLS_SOURCE_DIR}/library/asn1write.c"
  "${MBEDTLS_SOURCE_DIR}/library/base64.c"
  "${MBEDTLS_SOURCE_DIR}/library/bignum.c"
  "${MBEDTLS_SOURCE_DIR}/library/blowfish.c"
  "${MBEDTLS_SOURCE_DIR}/library/camellia.c"
  "${MBEDTLS_SOURCE_DIR}/library/ccm.c"
  "${MBEDTLS_SOURCE_DIR}/library/chacha20.c"
  "${MBEDTLS_SOURCE_DIR}/library/chachapoly.c"
  "${MBEDTLS_SOURCE_DIR}/library/cipher.c"
  "${MBEDTLS_SOURCE_DIR}/library/cipher_wrap.c"
  "${MBEDTLS_SOURCE_DIR}/library/cmac.c"
  "${MBEDTLS_SOURCE_DIR}/library/ctr_drbg.c"
  "${MBEDTLS_SOURCE_DIR}/library/debug.c"
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
  "${MBEDTLS_SOURCE_DIR}/library/hkdf.c"
  "${MBEDTLS_SOURCE_DIR}/library/hmac_drbg.c"
  "${MBEDTLS_SOURCE_DIR}/library/md.c"
  "${MBEDTLS_SOURCE_DIR}/library/md2.c"
  "${MBEDTLS_SOURCE_DIR}/library/md4.c"
  "${MBEDTLS_SOURCE_DIR}/library/md5.c"
  "${MBEDTLS_SOURCE_DIR}/library/memory_buffer_alloc.c"
  "${MBEDTLS_SOURCE_DIR}/library/net_sockets.c"
  "${MBEDTLS_SOURCE_DIR}/library/nist_kw.c"
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
  "${MBEDTLS_SOURCE_DIR}/library/platform_util.c"
  "${MBEDTLS_SOURCE_DIR}/library/poly1305.c"
  "${MBEDTLS_SOURCE_DIR}/library/ripemd160.c"
  "${MBEDTLS_SOURCE_DIR}/library/rsa.c"
  "${MBEDTLS_SOURCE_DIR}/library/rsa_internal.c"
  "${MBEDTLS_SOURCE_DIR}/library/sha1.c"
  "${MBEDTLS_SOURCE_DIR}/library/sha256.c"
  "${MBEDTLS_SOURCE_DIR}/library/sha512.c"
  "${MBEDTLS_SOURCE_DIR}/library/threading.c"
  "${MBEDTLS_SOURCE_DIR}/library/timing.c"
  "${MBEDTLS_SOURCE_DIR}/library/version.c"
  "${MBEDTLS_SOURCE_DIR}/library/version_features.c"
  "${MBEDTLS_SOURCE_DIR}/library/xtea.c"
  "${MBEDTLS_SOURCE_DIR}/library/aria.c"
  "${MBEDTLS_SOURCE_DIR}/library/chacha20.c"
  "${MBEDTLS_SOURCE_DIR}/library/chachapoly.c"
  "${MBEDTLS_SOURCE_DIR}/library/hkdf.c"
  "${MBEDTLS_SOURCE_DIR}/library/nist_kw.c"
  "${MBEDTLS_SOURCE_DIR}/library/platform_util.c"
  "${MBEDTLS_SOURCE_DIR}/library/poly1305.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto_se.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto_slot_management.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto_storage.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_its_file.c"
  "${MBEDTLS_SOURCE_DIR}/library/rsa_internal.c"
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
    "${MBEDTLS_SOURCE_DIR}/library/ssl_msg.c"
)

#set_source_files_properties("${MBEDTLS_SOURCE_DIR}/library/bignum.c" PROPERTIES COMPILE_FLAGS -Wno-overlength-strings)

set(SPDLOG_VERSION 1.8.1)
set(SPDLOG_SHA256 SHA256=eed0095a1d52d08a0834feda146d4f9148fa4125620cd04d8ea57e0238fa39cd)
set(SPDLOG_URL "${THIRD_PARTY_DIRECTORY}/spdlog-${SPDLOG_VERSION}.zip" CACHE STRING "URL to the spdlog lib repo")
ExternalProject_Add(lief_spdlog
  URL               ${SPDLOG_URL}
  URL_HASH          ${SPDLOG_SHA256}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(lief_spdlog SOURCE_DIR)
set(SPDLOG_SOURCE_DIR "${SOURCE_DIR}")

# Fuzzing
# ~~~~~~~
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


# Frozen
# ------
set(LIEF_FROZEN_ENABLED 0)

if (LIEF_SUPPORT_CXX14 AND NOT LIEF_DISABLE_FROZEN)
  message(STATUS "Enable Frozen (C++14 support)")
  set(LIEF_FROZEN_ENABLED 1)
  set(FROZEN_VERSION 1.0.0)
  set(FROZEN_SHA256 SHA256=35ed00f6e2eb718415bf7c3e62e7708318fa684b9cc736c3fe08cf4cb2f08305)
  set(FROZEN_URL "${THIRD_PARTY_DIRECTORY}/frozen-${FROZEN_VERSION}.zip" CACHE STRING "URL to Frozen")
  ExternalProject_Add(lief_frozen
    URL               ${FROZEN_URL}
    URL_HASH          ${FROZEN_SHA256}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    UPDATE_COMMAND    ""
    INSTALL_COMMAND   "")

  ExternalProject_get_property(lief_frozen SOURCE_DIR)
  set(FROZEN_INCLUDE_DIR "${SOURCE_DIR}/include")
endif()

