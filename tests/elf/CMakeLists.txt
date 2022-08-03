if (LIEF_EXAMPLES)
  file(GLOB_RECURSE SAMPLES_ELF
    "${LIEF_SAMPLES_DIRECTORY}/ELF/*.bin"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/*.so"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/*.pie"
    #"${LIEF_SAMPLES_DIRECTORY}/ELF/*.core"
  )

  list(REMOVE_ITEM SAMPLES_ELF
    "${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_tiny.bin"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_tiny01.bin"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_tiny-hello.bin"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_rvs.bin"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_tiny.bin")


  foreach(ELF_PATH ${SAMPLES_ELF})
    get_filename_component(ELF_NAME ${ELF_PATH} NAME)

    if (LIEF_C_API)
      add_test(EXAMPLES_C_elf_reader_${ELF_NAME}
               ${LIEF_EXAMPLES_BINARY_DIR}/c/elf_reader ${ELF_PATH})
    endif()

    # ELF Reader
    add_test(EXAMPLES_CPP_elf_reader_${ELF_NAME}
             ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_reader ${ELF_PATH})

    # ELF Strip
    add_test(EXAMPLES_CPP_elf_strip_${ELF_NAME}
      ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_strip
      ${ELF_PATH} ${CMAKE_CURRENT_BINARY_DIR}/${ELF_NAME}.strip)

    # Abstract Reader
    add_test(EXAMPLES_CPP_abstract_reader_${ELF_NAME}
      ${LIEF_EXAMPLES_BINARY_DIR}/cpp/abstract_reader
      ${ELF_PATH})

    # Add section
    if(${ELF_NAME} MATCHES "(.*)_binary_(.*)")
      if (NOT ${ELF_NAME} MATCHES "ELF64_x86-64_binary_systemd-resolve.bin") # TODO
      add_test(EXAMPLES_CPP_add_section_${ELF_NAME}
        ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_add_section
        ${ELF_PATH} ${CMAKE_CURRENT_BINARY_DIR}/${ELF_NAME}.section)
      endif()
    endif()

    # Elf Symbol
    add_test(EXAMPLES_CPP_elf_symbols_${ELF_NAME}
      ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_symbols
      ${ELF_PATH})

  endforeach()
endif()

# Fuzzer
# ------
if (UNIX AND NOT APPLE)
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/fuzzing.py.in" "${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py")

  add_test(FUZZER_ELF_bin_ls_x86
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py
      --input-seed=${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_ls.bin -n 100)

  add_test(FUZZER_ELF_bin_ls_arm
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py
      --input-seed=${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_ARM_binary_ls.bin -n 100)

  add_test(FUZZER_ELF_bin_nm_x86
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE}
      ${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py
      --input-seed=${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_nm.bin -n 100)
endif()


add_test(UNITTEST_PYTHON_elf
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/elf_test.py)

add_test(ELF_PYTHON_add_section
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/add_section.py)

add_test(ELF_PYTHON_add_segment
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/add_segment.py)

add_test(ELF_PYTHON_add_content
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/add_content.py)

add_test(ELF_PYTHON_replace_segment
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/replace_segment.py)

add_test(ELF_PYTHON_test_dynamic
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_dynamic.py)

add_test(ELF_PYTHON_test_static
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_static.py)

add_test(ELF_PYTHON_hash_tests
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/hash_tests.py)

add_test(ELF_PYTHON_test_bss
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_bss.py)
add_test(ELF_PYTHON_change_interpreter
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/change_interpreter.py)

add_test(ELF_PYTHON_notes
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_notes.py)

add_test(ELF_PYTHON_bin2lib
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_bin2lib.py)

add_test(ELF_PYTHON_modify_relocations
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/modify_relocations.py)

add_test(ELF_PYTHON_remove_section
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/remove_section.py)

  # ==
add_test(ELF_PYTHON_parser
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_parser.py)

add_test(ELF_PYTHON_equality
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_equality.py)

add_test(ELF_PYTHON_core
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/test_core.py)

add_test(ELF_PYTHON_issue_466
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_466.py)

add_test(ELF_PYTHON_issue_747
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_747.py)

add_test(ELF_PYTHON_issue_760
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_760.py)

add_test(ELF_PYTHON_empty_gnu_hash
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_empty_gnu_hash.py)

add_test(ELF_PYTHON_section_frame
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_section_frame.py)

add_test(ELF_builder
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_builder.py)

add_test(ELF_object_files
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_object_files.py)

add_test(ELF_binary_size
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_binary_size.py)

add_test(ELF_symbol_versions
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest -rsx
    ${CMAKE_CURRENT_SOURCE_DIR}/test_symbol_versions.py)


# Examples
# --------
add_test(EXAMPLE_PYTHON_elf_reader_ls
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/elf_reader.py --all
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_ls.bin)

add_test(EXAMPLE_PYTHON_elf_reader_arm
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/elf_reader.py --all
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_ARM_binary_ls.bin)

add_test(EXAMPLE_PYTHON_elf_remove_sections_table
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/elf_remove_section_table.py
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_ls.bin
    ${CMAKE_CURRENT_BINARY_DIR}/ls_without_sections)

add_test(EXAMPLE_PYTHON_elf_symbol_obfuscation
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/elf_symbol_obfuscation.py
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_ls.bin
    ${CMAKE_CURRENT_BINARY_DIR}/ls_symbol_obfuscated)

add_test(EXAMPLE_PYTHON_elf_unstrip
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/elf_unstrip.py
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_ls.bin
    ${CMAKE_CURRENT_BINARY_DIR}/ls_unstriped)

add_test(EXAMPLE_PYTHON_elf_json
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/elf_json.py
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_ls.bin)
