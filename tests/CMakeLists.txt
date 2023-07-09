enable_testing()

if (NOT LIEF_ELF OR NOT LIEF_PE OR NOT LIEF_MACHO)
  message(FATAL_ERROR "Tests require all LIEF's modules activated" )
endif()

set(LIEF_EXAMPLES_DIRECTORY  "${PROJECT_SOURCE_DIR}/examples")
set(LIEF_EXAMPLES_BINARY_DIR "${PROJECT_BINARY_DIR}/examples")

# Fuzzing
# =======
if(UNIX AND NOT APPLE)
  set(MELKOR_VERSION ac2495b) # From the fork: https://github.com/romainthomas/elf_fuzzer
  set(MELKOR_SHA256 SHA256=8cccc4ca5e05e305215cc74761413746b660b76f5869a563f52cec1f23d79f2e)
  set(MELKOR_URL "${THIRD_PARTY_DIRECTORY}/Melkor_ELF_Fuzzer-${MELKOR_VERSION}.zip" CACHE STRING "URL to the Melkor package")

  set(MELKOR_PREFIX      "${CMAKE_CURRENT_BINARY_DIR}/Melkor")
  set(MELKOR_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/Melkor")
  ExternalProject_Add(MELKOR
   PREFIX            ${MELKOR_PREFIX}
   URL               ${MELKOR_URL}
   URL_HASH          ${MELKOR_SHA256}
   INSTALL_DIR       ${MELKOR_INSTALL_DIR}
   UPDATE_COMMAND    ""
   CONFIGURE_COMMAND ""
   INSTALL_COMMAND   ""
   BUILD_COMMAND     make clean && make
   BUILD_IN_SOURCE   ON)

  ExternalProject_get_property(MELKOR SOURCE_DIR)
  set(MELKOR_BINARY "${SOURCE_DIR}/melkor")
  message(STATUS "${MELKOR_BINARY}")
endif()

add_subdirectory(unittests)

if (CMAKE_CONFIGURATION_TYPES)
  add_custom_target(check-lief
    COMMAND ${CMAKE_CTEST_COMMAND} --parallel 1 --progress --output-on-failure --build-config "$<CONFIGURATION>")
else()
  add_custom_target(check-lief
    COMMAND ${CMAKE_CTEST_COMMAND} --parallel 1 --progress --output-on-failure)
endif()
