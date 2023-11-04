include(CheckCCompilerFlag)

set(LIEF_ELF_C_EXAMPLES
  elf_reader.c)

set(LIEF_PE_C_EXAMPLES
  pe_reader.c)

set(LIEF_MACHO_C_EXAMPLES
  macho_reader.c)

set(LIEF_C_EXAMPLES)

if (LIEF_ELF)
  set(LIEF_C_EXAMPLES "${LIEF_C_EXAMPLES}" "${LIEF_ELF_C_EXAMPLES}")
endif()

if (LIEF_PE)
  set(LIEF_C_EXAMPLES "${LIEF_C_EXAMPLES}" "${LIEF_PE_C_EXAMPLES}")
endif()

if (LIEF_MACHO)
  set(LIEF_C_EXAMPLES "${LIEF_C_EXAMPLES}" "${LIEF_MACHO_C_EXAMPLES}")
endif()

if (LIEF_C_API)
foreach(example ${LIEF_C_EXAMPLES})
  string(REGEX REPLACE ".c\$" "" output_target "c_${example}")
  string(REGEX REPLACE ".c\$" "" output_name "${example}")

  add_executable("${output_target}" "${example}")

  target_include_directories(${output_target} PUBLIC
    $<TARGET_PROPERTY:LIB_LIEF,INCLUDE_DIRECTORIES>)

  set(LIEF_EXAMPLES_C_FLAGS)
  CHECK_C_COMPILER_FLAG("-ansi" HAS_ANSI)
  if (HAS_ANSI)
    set(LIEF_EXAMPLES_C_FLAGS ${LIEF_EXAMPLES_C_FLAGS} -ansi)
  endif()

  set_property(TARGET "${output_target}" PROPERTY C_STANDARD          99)
  set_property(TARGET "${output_target}" PROPERTY C_STANDARD_REQUIRED ON)

  target_compile_options("${output_target}" PRIVATE ${LIEF_EXAMPLES_C_FLAGS})

  if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if (UNIX)
      if (LIEF_FORCE32)
        target_compile_options("${output_target}" PRIVATE -m32)
        set_property(TARGET "${output_target}" PROPERTY LINK_FLAGS -m32)
      endif()
    endif()
  endif()



  set_target_properties("${output_target}" PROPERTIES OUTPUT_NAME "${output_name}")
  target_link_libraries ("${output_target}" LIB_LIEF)
endforeach()
endif()


if (LIEF_INSTALL)
  install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION share/LIEF/examples/c
    COMPONENT examples
    FILES_MATCHING REGEX "(.*).(hpp|h|c)$"
  )
endif()

