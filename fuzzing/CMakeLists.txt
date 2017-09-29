include(ProcessorCount)
set(LIEF_FUZZER_SRC
  elf_fuzzer.cpp
  pe_fuzzer.cpp
  macho_fuzzer.cpp
)

foreach(fuzzer ${LIEF_FUZZER_SRC})
  string(REGEX REPLACE ".cpp\$" "" output "${fuzzer}")
  add_executable("${output}"        "${fuzzer}")
  add_executable("${output}_shared" "${fuzzer}")

  # Don't use default include dir
  set_property(TARGET "${output}" "${output}_shared" PROPERTY INCLUDE_DIRECTORIES "")

  set_property(TARGET "${output}" "${output}_shared" PROPERTY CXX_STANDARD           11)
  set_property(TARGET "${output}" "${output}_shared" PROPERTY CXX_STANDARD_REQUIRED  ON)

  target_link_libraries("${output}"        PUBLIC LIB_LIEF_STATIC)
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
  #UPDATE_COMMAND    ${GIT_EXECUTABLE} pull
  UPDATE_COMMAND    ""
)

ExternalProject_Get_Property(lief_fuzzer_corpus source_dir)
set(LIEF_CORUPUS_DIRECTORY "${source_dir}" CACHE INTERNAL "Path to LIEF samples")
message(STATUS "Samples directory: ${LIEF_CORUPUS_DIRECTORY}")


ProcessorCount(N)
set(LIB_FUZZER_ARGS -detect_leaks=1 -rss_limit_mb=0 -print_final_stats=1 -jobs=${N})
set(ASAN_OPTIONS allocator_may_return_null=1)
# ELF
# ===
set(ELF_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/elf-output)

add_custom_target(build-elf-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E make_directory ${ELF_WORKING_DIR})

add_custom_target("fuzz-elf"
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=${ASAN_OPTIONS} ${CMAKE_CURRENT_BINARY_DIR}/elf_fuzzer ${LIEF_CORUPUS_DIRECTORY}/ELF ${LIB_FUZZER_ARGS}
  DEPENDS elf_fuzzer LIB_LIEF_STATIC build-elf-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${ELF_WORKING_DIR}
  COMMENT "Run ELF fuzzer")


# PE
# ==
set(PE_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/pe-output)

add_custom_target(build-pe-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PE_WORKING_DIR})

add_custom_target("fuzz-pe"
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS="${ASAN_OPTIONS}" ${CMAKE_CURRENT_BINARY_DIR}/pe_fuzzer ${LIEF_CORUPUS_DIRECTORY}/PE ${LIB_FUZZER_ARGS}
  DEPENDS pe_fuzzer LIB_LIEF_STATIC build-pe-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${PE_WORKING_DIR}
  COMMENT "Run PE fuzzer")

# MachO
# =====
set(MACHO_WORKING_DIR ${CMAKE_CURRENT_BINARY_DIR}/macho-output)

add_custom_target(build-macho-fuzz-output
    COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=${ASAN_OPTIONS} ${CMAKE_COMMAND} -E make_directory ${MACHO_WORKING_DIR})

add_custom_target("fuzz-macho"
  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/macho_fuzzer ${LIEF_CORUPUS_DIRECTORY}/MachO ${LIB_FUZZER_ARGS}
  DEPENDS macho_fuzzer LIB_LIEF_STATIC build-macho-fuzz-output lief_fuzzer_corpus
  WORKING_DIRECTORY ${MACHO_WORKING_DIR}
  COMMENT "Run MachO fuzzer")



