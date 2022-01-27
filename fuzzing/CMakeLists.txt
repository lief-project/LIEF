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

  set_target_properties(
    "${output}"
    PROPERTIES POSITION_INDEPENDENT_CODE ON
               CXX_STANDARD              11
               CXX_STANDARD_REQUIRED     ON)

  set_property(TARGET "${output}"
               APPEND PROPERTY LINK_FLAGS -fsanitize=fuzzer)

  # Don't use default include dir
  #set_property(TARGET "${output}" "${output}_shared" PROPERTY INCLUDE_DIRECTORIES "")

  target_link_libraries("${output}" PUBLIC LIB_LIEF asan)
endforeach()


