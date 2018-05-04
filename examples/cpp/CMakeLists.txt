set(LIEF_ELF_CPP_EXAMPLES
  elf_reader.cpp
  elf_add_section.cpp
  elf_builder.cpp
  elf_section_rename.cpp
  elf_strip.cpp
  elf_symbols.cpp
)

set(LIEF_PE_CPP_EXAMPLES
  pe_builder.cpp
  pe_reader.cpp
)

set(LIEF_MACHO_CPP_EXAMPLES
  macho_reader.cpp
  macho_instrumentation.cpp
  macho_builder.cpp
)

set(LIEF_OAT_CPP_EXAMPLES
  oat_reader.cpp
)

set(LIEF_VDEX_CPP_EXAMPLES
  vdex_reader.cpp
)

set(LIEF_ART_CPP_EXAMPLES
  art_reader.cpp
)

set(LIEF_DEX_CPP_EXAMPLES
  dex_reader.cpp
)

set(LIEF_CPP_EXAMPLES
  abstract_reader.cpp
  logging.cpp
  benchmark.cpp
)

if (LIEF_ELF)
  set(LIEF_CPP_EXAMPLES "${LIEF_CPP_EXAMPLES}" "${LIEF_ELF_CPP_EXAMPLES}")
endif()

if (LIEF_PE)
  set(LIEF_CPP_EXAMPLES "${LIEF_CPP_EXAMPLES}" "${LIEF_PE_CPP_EXAMPLES}")
endif()

if (LIEF_MACHO)
  set(LIEF_CPP_EXAMPLES "${LIEF_CPP_EXAMPLES}" "${LIEF_MACHO_CPP_EXAMPLES}")
endif()

if (LIEF_OAT)
  set(LIEF_CPP_EXAMPLES ${LIEF_CPP_EXAMPLES} ${LIEF_OAT_CPP_EXAMPLES})
endif()

if (LIEF_VDEX)
  set(LIEF_CPP_EXAMPLES ${LIEF_CPP_EXAMPLES} ${LIEF_VDEX_CPP_EXAMPLES})
endif()

if (LIEF_ART)
  set(LIEF_CPP_EXAMPLES ${LIEF_CPP_EXAMPLES} ${LIEF_ART_CPP_EXAMPLES})
endif()

if (LIEF_DEX)
  set(LIEF_CPP_EXAMPLES ${LIEF_CPP_EXAMPLES} ${LIEF_DEX_CPP_EXAMPLES})
endif()


foreach(example ${LIEF_CPP_EXAMPLES})
  string(REGEX REPLACE ".cpp\$" "" output_name "${example}")
  add_executable("${output_name}"        "${example}")
  add_executable("${output_name}_shared" "${example}")

  # Don't use default include dir
  set_property(TARGET "${output_name}" "${output_name}_shared" PROPERTY INCLUDE_DIRECTORIES "")

  if (MSVC)
    target_compile_options("${output_name}"        PUBLIC /FIiso646.h)
    target_compile_options("${output_name}_shared" PUBLIC /FIiso646.h)

    if (CMAKE_BUILD_TYPE MATCHES "Debug")
      target_compile_options("${output_name}_shared" PUBLIC /MTd)
    else()
      target_compile_options("${output_name}_shared" PUBLIC /MT)
    endif()

	  set_property(TARGET "${output_name}" "${output_name}_shared" PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
  endif()

  set_property(TARGET "${output_name}" "${output_name}_shared" PROPERTY CXX_STANDARD           11)
  set_property(TARGET "${output_name}" "${output_name}_shared" PROPERTY CXX_STANDARD_REQUIRED  ON)

  if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if (UNIX)
      if (LIEF_FORCE32)
        target_compile_options("${output_name}"        PRIVATE -m32)
        target_compile_options("${output_name}_shared" PRIVATE -m32)

        set_property(TARGET "${output_name}"        PROPERTY LINK_FLAGS -m32)
        set_property(TARGET "${output_name}_shared" PROPERTY LINK_FLAGS -m32)
      endif()
    endif()
  endif()

  target_link_libraries("${output_name}"        PUBLIC LIB_LIEF_STATIC)
  target_link_libraries("${output_name}_shared" PUBLIC LIB_LIEF_SHARED)
endforeach()


install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
  DESTINATION share/LIEF/examples/cpp
  COMPONENT examples
  FILES_MATCHING REGEX "(.*).(hpp|h|cpp)$"
)

