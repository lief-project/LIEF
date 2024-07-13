set(LIEF_CPP_EXAMPLES
  logging.cpp
  abstract_reader.cpp
  benchmark.cpp
  dwarf_inspect.cpp
  pdb_inspect.cpp
  objc_inspect.cpp
)

if (LIEF_ELF)
  list(APPEND LIEF_CPP_EXAMPLES
    elf_reader.cpp
    elf_add_section.cpp
    elf_builder.cpp
    elf_section_rename.cpp
    elf_strip.cpp
    elf_symbols.cpp
  )
endif()

if (LIEF_PE)
  list(APPEND LIEF_CPP_EXAMPLES
    pe_builder.cpp
    pe_reader.cpp
    pe_authenticode_check.cpp
  )
endif()

if (LIEF_MACHO)
  list(APPEND LIEF_CPP_EXAMPLES
    macho_reader.cpp
    macho_builder.cpp
  )
endif()

if (LIEF_OAT)
  list(APPEND LIEF_CPP_EXAMPLES
    oat_reader.cpp
  )
endif()

if (LIEF_VDEX)
  list(APPEND LIEF_CPP_EXAMPLES
    vdex_reader.cpp
  )
endif()

if (LIEF_ART)
  list(APPEND LIEF_CPP_EXAMPLES
    art_reader.cpp
  )
endif()

if (LIEF_DEX)
  list(APPEND LIEF_CPP_EXAMPLES
    dex_reader.cpp
  )
endif()

if(APPLE)
  list(APPEND LIEF_CPP_EXAMPLES
    macho_from_memory.cpp
  )
endif()

foreach(example ${LIEF_CPP_EXAMPLES})
  string(REGEX REPLACE ".cpp\$" "" output_name "${example}")
  add_executable(${output_name} ${example})

  # Don't use default include dir
  set_property(TARGET "${output_name}"
    PROPERTY INCLUDE_DIRECTORIES ""
  )

  set_target_properties(
    ${output_name}
    PROPERTIES POSITION_INDEPENDENT_CODE ON
               CXX_STANDARD              11
               CXX_STANDARD_REQUIRED     ON)

  target_link_libraries(${output_name} PUBLIC LIB_LIEF)

  if (CMAKE_BUILD_TYPE MATCHES "Release")
    if (UNIX AND NOT APPLE)
        add_custom_command(
          TARGET ${output_name}
          COMMENT "Strip ${output_name}"
          POST_BUILD
          COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:${output_name}>
        )
    endif()

    if (APPLE)
      add_custom_command(
        TARGET ${output_name}
        COMMENT "Strip ${output_name}"
        POST_BUILD
        COMMAND ${CMAKE_STRIP} -x -S $<TARGET_FILE:${output_name}>
      )
    endif()
  endif()

  if(LIEF_INSTALL_COMPILED_EXAMPLES)
    install(
      TARGETS ${output_name}
      RUNTIME DESTINATION bin
      BUNDLE DESTINATION bin
      COMPONENT examples)
  endif()
endforeach()

if (LIEF_INSTALL)
  install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION share/LIEF/examples/cpp
    COMPONENT examples
    FILES_MATCHING REGEX "(.*).(hpp|h|cpp)$"
  )
endif()
