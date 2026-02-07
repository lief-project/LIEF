if(__add_lief_dependencies)
  return()
endif()
set(__add_lief_dependencies ON)

# Json
# ----
if(LIEF_ENABLE_JSON)
  if(NOT LIEF_OPT_NLOHMANN_JSON_EXTERNAL)
    set(LIBJSON_VERSION 3.12.0)
    set(LIBJSON_SHA256 SHA256=6a2249e5d61c2a8351abfac218e08e9a43426dddb493950d30f3b8acfbbc648d)
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
  endif()
  message(STATUS "Enable JSON support")
  set(ENABLE_JSON_SUPPORT 1)
else()
  message(STATUS "Disable JSON support")
  set(ENABLE_JSON_SUPPORT 0)
endif()


# mbed TLS
# --------
if(NOT LIEF_OPT_MBEDTLS_EXTERNAL)
  set(MBED_TLS_VERSION 4.0.0.r0.gec4044008d)
  set(MBED_TLS_SHA256 SHA256=01aec4471547dec5308853ff0d797611a68a521a10496898b626035dfdc07183)
  set(MBED_TLS_URL "${THIRD_PARTY_DIRECTORY}/mbedtls-${MBED_TLS_VERSION}.zip" CACHE STRING "URL to MbedTLS")
  set(MBED_TLS_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/mbed_tls")

  set(SOURCE_DIR mbed_src)
  set(MBEDTLS_SOURCE_DIR "${SOURCE_DIR}")
  set(MBEDTLS_INCLUDE_DIRS )

  list(APPEND MBEDTLS_INCLUDE_DIRS
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/include"
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/library"
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/tf-psa-crypto/include"
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include"
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/tf-psa-crypto/core"
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src"
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/tf-psa-crypto/drivers/everest/include/tf-psa-crypto/private/everest"
    "${CMAKE_CURRENT_BINARY_DIR}/${SOURCE_DIR}/tf-psa-crypto/drivers/everest/include/tf-psa-crypto/private/everest/kremlib"
  )

  set(mbedtls_src_files
    "${MBEDTLS_SOURCE_DIR}/library/debug.c"
    #"${MBEDTLS_SOURCE_DIR}/library/mbedtls_config.c"
    "${MBEDTLS_SOURCE_DIR}/library/mps_reader.c"
    "${MBEDTLS_SOURCE_DIR}/library/mps_trace.c"
    "${MBEDTLS_SOURCE_DIR}/library/net_sockets.c"
    "${MBEDTLS_SOURCE_DIR}/library/pkcs7.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_cache.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_ciphersuites.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_client.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_cookie.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_msg.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_ticket.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls12_client.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls12_server.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls13_client.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls13_generic.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls13_keys.c"
    "${MBEDTLS_SOURCE_DIR}/library/ssl_tls13_server.c"
    "${MBEDTLS_SOURCE_DIR}/library/timing.c"
    "${MBEDTLS_SOURCE_DIR}/library/version.c"
    "${MBEDTLS_SOURCE_DIR}/library/error.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_create.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_crl.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_crt.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_csr.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_oid.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509write.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509write_crt.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509write_csr.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/psa_crypto.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/psa_crypto_client.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/psa_crypto_slot_management.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/psa_crypto_storage.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/psa_its_file.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/tf_psa_crypto_config.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/tf_psa_crypto_version.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/core/psa_crypto_driver_wrappers_no_static.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/aes.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/aesce.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/aesni.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/aria.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/asn1parse.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/asn1write.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/base64.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/bignum.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/bignum_core.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/bignum_mod.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/bignum_mod_raw.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/block_cipher.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/camellia.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ccm.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/chacha20.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/chachapoly.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/cipher.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/cipher_wrap.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/cmac.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/constant_time.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ctr_drbg.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ecdh.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ecdsa.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ecjpake.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ecp.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ecp_curves.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ecp_curves_new.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/entropy.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/entropy_poll.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/gcm.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/hmac_drbg.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/lmots.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/lms.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/md.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/md5.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/memory_buffer_alloc.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/nist_kw.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/oid.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pem.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pk.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pk_ecc.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pk_rsa.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pk_wrap.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pkcs5.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pkparse.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/pkwrite.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/platform.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/platform_util.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/poly1305.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_aead.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_cipher.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_ecp.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_ffdh.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_hash.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_mac.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_pake.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_crypto_rsa.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/psa_util.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/ripemd160.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/rsa.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/rsa_alt_helpers.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/sha1.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/sha256.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/sha3.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/sha512.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/src/threading.c"

    #"${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/everest/library/Hacl_Curve25519.c"
    #"${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/everest/library/Hacl_Curve25519_joined.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/everest/library/everest.c"
    #"${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/everest/library/legacy/Hacl_Curve25519.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/everest/library/x25519.c"

    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/p256-m/p256-m/p256-m.c"
    "${MBEDTLS_SOURCE_DIR}/tf-psa-crypto/drivers/p256-m/p256-m_driver_entrypoints.c"
  )

  ExternalProject_Add(lief_mbed_tls
    SOURCE_DIR        ${SOURCE_DIR}
    PREFIX            ${MBED_TLS_PREFIX}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    URL               ${MBED_TLS_URL}
    URL_HASH          ${MBED_TLS_SHA256}
    UPDATE_COMMAND    "" # repetitive update are a pain
    BUILD_BYPRODUCTS  ${mbedtls_src_files})
endif()

add_library(lief_spdlog INTERFACE)

if(LIEF_EXTERNAL_SPDLOG)
  find_package(spdlog 1.17.0 REQUIRED)
  list(APPEND CMAKE_MODULE_PATH "${SPDLOG_DIR}/cmake")
  target_link_libraries(lief_spdlog INTERFACE spdlog::spdlog)
  get_target_property(SPDLOG_INC_DIR spdlog::spdlog INTERFACE_INCLUDE_DIRECTORIES)
  target_include_directories(lief_spdlog SYSTEM INTERFACE ${SPDLOG_INC_DIR})
else()
  set(SPDLOG_VERSION 1.17.0)
  set(SPDLOG_SHA256 SHA256=b11912a82d149792fef33fabd0503b13d54aeac25c1464755461d4108ea71fc2)
  set(SPDLOG_URL "${THIRD_PARTY_DIRECTORY}/spdlog-${SPDLOG_VERSION}.zip" CACHE STRING "URL to the spdlog source")
  ExternalProject_Add(lief_spdlog_project
    URL               ${SPDLOG_URL}
    URL_HASH          ${SPDLOG_SHA256}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    UPDATE_COMMAND    ""
    INSTALL_COMMAND   "")

  ExternalProject_get_property(lief_spdlog_project SOURCE_DIR)
  set(SPDLOG_SOURCE_DIR "${SOURCE_DIR}")
  add_dependencies(lief_spdlog lief_spdlog_project)
  target_include_directories(lief_spdlog SYSTEM INTERFACE "$<BUILD_INTERFACE:${SPDLOG_SOURCE_DIR}/include>")
endif()

# Frozen
# ------
set(LIEF_FROZEN_ENABLED 0)

if (LIEF_SUPPORT_CXX14 AND NOT LIEF_DISABLE_FROZEN)
  message(STATUS "Enable Frozen (C++14 support)")
  set(LIEF_FROZEN_ENABLED 1)

  if (NOT LIEF_OPT_FROZEN_EXTERNAL)
    set(FROZEN_VERSION 61dce5a)
    set(FROZEN_SHA256 SHA256=c94ba33d5369749e8d8ba12fb87d60de02ddac981051383a8d321968abb6a314)
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
endif()

# expected
# ----------
if(NOT LIEF_EXTERNAL_EXPECTED)
  set(EXPECTED_VERSION 1.3.1)
  set(EXPECTED_SHA256 SHA256=68bbfd81a6d312c4518b5a1831f465fa03811355af9aa9c7403348545d1d2a56)
  set(EXPECTED_URL "${THIRD_PARTY_DIRECTORY}/expected-${EXPECTED_VERSION}.zip" CACHE STRING "URL to Expected")
  ExternalProject_Add(lief_expected
    URL               ${EXPECTED_URL}
    URL_HASH          ${EXPECTED_SHA256}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    UPDATE_COMMAND    ""
    INSTALL_COMMAND   "")

  ExternalProject_get_property(lief_expected SOURCE_DIR)
  set(EXPECTED_SRC_DIR "${SOURCE_DIR}")
endif()

# utfcpp
# ------
if(NOT LIEF_OPT_UTFCPP_EXTERNAL)
  set(UTFCPP_VERSION 4.0.9)
  set(UTFCPP_SHA256 SHA256=73802895d0cf7b000cdf8e6ee5d69b963a829d4ea419562afd8f190adef87d5f)
  set(UTFCPP_URL "${THIRD_PARTY_DIRECTORY}/utfcpp-${UTFCPP_VERSION}.zip" CACHE STRING "URL to UTFCPP")
  ExternalProject_Add(lief_utfcpp
    URL               ${UTFCPP_URL}
    URL_HASH          ${UTFCPP_SHA256}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    UPDATE_COMMAND    ""
    INSTALL_COMMAND   "")

  ExternalProject_get_property(lief_utfcpp SOURCE_DIR)
  set(UTFCPP_INCLUDE_DIR "${SOURCE_DIR}/source")
endif()

# https://github.com/tcbrindle/span
# ---------------------------------
if(NOT LIEF_EXTERNAL_SPAN)
  set(TCB_SPAN_VERSION b70b0ff)
  set(TCB_SPAN_SHA256 SHA256=f3d47ed83507fce94245a9f3cf97bc433cd1116f94d11ac0dca1a6f53bbeb239)
  set(TCB_SPAN_URL "${THIRD_PARTY_DIRECTORY}/tcb-span-${TCB_SPAN_VERSION}.zip" CACHE STRING "URL to tcb/span")
  ExternalProject_Add(lief_span
    URL               ${TCB_SPAN_URL}
    URL_HASH          ${TCB_SPAN_SHA256}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    UPDATE_COMMAND    ""
    INSTALL_COMMAND   "")

  ExternalProject_get_property(lief_span SOURCE_DIR)
  set(TCB_SPAN_SRC_DIR "${SOURCE_DIR}")
endif()
