include(ProcessorCount)
set(LIEF_FUZZER_SRC
  elf_fuzzer.cpp
  pe_fuzzer.cpp
  macho_fuzzer.cpp
  pme_fuzzer.cpp
  pkcs7_signature.cpp
)

foreach(fuzzer ${LIEF_FUZZER_SRC})
  string(REGEX REPLACE ".cpp\$" "" output "${fuzzer}")
  add_executable("${output}"        "${fuzzer}")
  add_executable("${output}_shared" "${fuzzer}")

  # Don't use default include dir
  set_property(TARGET "${output}" "${output}_shared" PROPERTY INCLUDE_DIRECTORIES "")

  set_property(TARGET "${output}" "${output}_shared" PROPERTY CXX_STANDARD           11)
  set_property(TARGET "${output}" "${output}_shared" PROPERTY CXX_STANDARD_REQUIRED  ON)

  target_link_libraries("${output}"        PUBLIC LIB_LIEF)
  target_link_libraries("${output}_shared" PUBLIC LIB_LIEF_SHARED)

endforeach()


# Corpus from lief-samples
set(SAMPLES_GIT_URL "https://github.com/lief-project/samples.git" CACHE STRING "URL to tests samples")
set(SAMPLES_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/corpus")
set(SAMPLES_TAG master)

ExternalProject_Add(lief_fuzzer_corpus
  PREFIX            ${SAMPLES_PREFIX}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
  GIT_REPOSITORY    ${SAMPLES_GIT_URL}
  GIT_TAG           ${SAMPLES_TAG}
  GIT_SHALLOW       TRUE
  GIT_PROGRESS      TRUE
  UPDATE_COMMAND    ""
  LOG_DOWNLOAD 1
)

find_package(PythonInterp)
if (PythonInterp_FOUND OR PYTHON_EXECUTABLE)
  ExternalProject_Add_Step(lief_fuzzer_corpus cleanup
    DEPENDEES download
    DEPENDERS build
    WORKING_DIRECTORY <SOURCE_DIR>
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/clean-corpus.py <SOURCE_DIR>
  )
endif()

ExternalProject_Get_Property(lief_fuzzer_corpus source_dir)
set(LIEF_CORUPUS_DIRECTORY "${source_dir}" CACHE INTERNAL "Path to LIEF samples")
message(STATUS "Samples directory: ${LIEF_CORUPUS_DIRECTORY}")


ProcessorCount(N)
set(LIB_FUZZER_ARGS -detect_leaks=1 -rss_limit_mb=4096 -max_total_time=5400 -print_final_stats=1 -jobs=${N})
set(ASAN_OPTIONS allocator_may_return_null=1)

# PME
# ===
set(PME_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/pme-output)
set(PME_NEW_CASES   ${PME_WORKING_DIR}/new_cases)

add_custom_target(build-pme-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PME_WORKING_DIR} ${PME_NEW_CASES})

add_custom_target("fuzz"
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=${ASAN_OPTIONS} ${CMAKE_CURRENT_BINARY_DIR}/pme_fuzzer ${LIB_FUZZER_ARGS} ${LIEF_CORUPUS_DIRECTORY} ${PME_NEW_CASES}
  DEPENDS pme_fuzzer LIB_LIEF build-pme-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${PME_WORKING_DIR}
  COMMENT "Run fuzzer on the 3 formats")



# ELF
# ===
set(ELF_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/elf-output)
set(ELF_NEW_CASES ${ELF_WORKING_DIR}/new_cases)

add_custom_target(build-elf-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E make_directory ${ELF_WORKING_DIR} ${ELF_NEW_CASES})

add_custom_target("fuzz-elf"
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=${ASAN_OPTIONS} ${CMAKE_CURRENT_BINARY_DIR}/elf_fuzzer ${LIB_FUZZER_ARGS} ${LIEF_CORUPUS_DIRECTORY}/ELF ${ELF_NEW_CASES}
  DEPENDS elf_fuzzer LIB_LIEF build-elf-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${ELF_WORKING_DIR}
  COMMENT "Run ELF fuzzer")


# PE
# ==
set(PE_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/pe-output)
set(PE_NEW_CASES ${PE_WORKING_DIR}/new_cases)

add_custom_target(build-pe-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PE_WORKING_DIR} ${PE_NEW_CASES})

add_custom_target("fuzz-pe"
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS="${ASAN_OPTIONS}" ${CMAKE_CURRENT_BINARY_DIR}/pe_fuzzer ${LIB_FUZZER_ARGS}  ${PE_NEW_CASES} ${LIEF_CORUPUS_DIRECTORY}/PE
  DEPENDS pe_fuzzer LIB_LIEF build-pe-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${PE_WORKING_DIR}
  COMMENT "Run PE fuzzer")

# MachO
# =====
set(MACHO_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/macho-output)
set(MACHO_NEW_CASES ${MACHO_WORKING_DIR}/new_cases)

add_custom_target(build-macho-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E make_directory ${MACHO_WORKING_DIR} ${MACHO_NEW_CASES})

add_custom_target("fuzz-macho"
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS="${ASAN_OPTIONS}" ${CMAKE_CURRENT_BINARY_DIR}/macho_fuzzer ${LIB_FUZZER_ARGS} ${LIEF_CORUPUS_DIRECTORY}/MachO ${MACHO_NEW_CASES}
  DEPENDS macho_fuzzer LIB_LIEF build-macho-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${MACHO_WORKING_DIR}
  COMMENT "Run MachO fuzzer")


# PKCS7-Signature parsing
# =======================
set(PKCS7_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/pkcs7-output)
set(PKCS7_NEW_CASES ${PKCS7_WORKING_DIR}/new_cases)

add_custom_target(build-pkcs7-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PKCS7_WORKING_DIR} ${PKCS7_NEW_CASES})

add_custom_target("fuzz-pkcs7"
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS="${ASAN_OPTIONS}" ${CMAKE_CURRENT_BINARY_DIR}/pkcs7_signature ${LIB_FUZZER_ARGS} ${LIEF_CORUPUS_DIRECTORY}/pkcs7 ${PKCS7_NEW_CASES}
  DEPENDS pkcs7_signature LIB_LIEF build-pkcs7-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${PKCS7_WORKING_DIR}
  COMMENT "Run PKCS7 fuzzer")


