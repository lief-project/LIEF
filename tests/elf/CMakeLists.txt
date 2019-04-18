cmake_minimum_required(VERSION 3.1)
include(ExternalProject)

# Targets
# =======

# Examples tests
# ==============
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
      add_test(
        NAME EXAMPLES_C_elf_reader_${ELF_NAME}
        COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/c/elf_reader
        ${ELF_PATH})
    endif()

    # ELF Reader
    add_test(
      NAME EXAMPLES_CPP_elf_reader_${ELF_NAME}
      COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_reader
      ${ELF_PATH})

    # ELF Strip
    add_test(
      NAME EXAMPLES_CPP_elf_strip_${ELF_NAME}
      COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_strip
      ${ELF_PATH}
      ${CMAKE_CURRENT_BINARY_DIR}/${ELF_NAME}.strip)

    # Abstract Reader
    add_test(
      NAME EXAMPLES_CPP_abstract_reader_${ELF_NAME}
      COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/abstract_reader
      ${ELF_PATH})

    # Add section
    if(${ELF_NAME} MATCHES "(.*)_binary_(.*)")
      if (NOT ${ELF_NAME} MATCHES "ELF64_x86-64_binary_systemd-resolve.bin") # TODO
      add_test(
        NAME EXAMPLES_CPP_add_section_${ELF_NAME}
        COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_add_section
        ${ELF_PATH}
        ${CMAKE_CURRENT_BINARY_DIR}/${ELF_NAME}.section)
      endif()
    endif()

    # Elf Symbol
    add_test(
      NAME EXAMPLES_CPP_elf_symbols_${ELF_NAME}
      COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/elf_symbols
      ${ELF_PATH})

  endforeach()
endif()

# Python tests
# ============
if (PYTHON_TESTS_ENABLED)

  # Fuzzer
  # ------
  if (UNIX AND NOT APPLE)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/fuzzing.py.in" "${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py")
    ADD_PYTHON_TEST(FUZZER_ELF_bin_ls_x86
        ${PYTHON_EXECUTABLE}
        "${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py \
        --input-seed=${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_ls.bin -n 100")


    ADD_PYTHON_TEST(FUZZER_ELF_bin_ls_arm
        ${PYTHON_EXECUTABLE}
        "${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py \
        --input-seed=${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_ARM_binary_ls.bin -n 100")


    ADD_PYTHON_TEST(FUZZER_ELF_bin_nm_x86
        ${PYTHON_EXECUTABLE}
        "${CMAKE_CURRENT_BINARY_DIR}/fuzzing.py \
        --input-seed=${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_nm.bin -n 100")
  endif()

  # Unit tests
  # ----------
  ADD_PYTHON_TEST(UNITTEST_PYTHON_elf
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/elf_test.py")


  ADD_PYTHON_TEST(ELF_PYTHON_add_section
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/add_section.py")

  ADD_PYTHON_TEST(ELF_PYTHON_add_segment
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/add_segment.py")


  ADD_PYTHON_TEST(ELF_PYTHON_add_content
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/add_content.py")


  ADD_PYTHON_TEST(ELF_PYTHON_replace_segment
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/replace_segment.py")


  ADD_PYTHON_TEST(ELF_PYTHON_test_dynamic
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_dynamic.py")

  ADD_PYTHON_TEST(ELF_PYTHON_test_static
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_static.py")

  ADD_PYTHON_TEST(ELF_PYTHON_hash_test
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/hash_tests.py")


  ADD_PYTHON_TEST(ELF_PYTHON_change_interpreter
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/change_interpreter.py")


  ADD_PYTHON_TEST(ELF_PYTHON_notes
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_notes.py")


  ADD_PYTHON_TEST(ELF_PYTHON_bin2lib
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_bin2lib.py")

  ADD_PYTHON_TEST(ELF_PYTHON_modify_relocations
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/modify_relocations.py")

  ADD_PYTHON_TEST(ELF_PYTHON_remove_section
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/remove_section.py")

  ADD_PYTHON_TEST(ELF_PYTHON_parser
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_parser.py")

  ADD_PYTHON_TEST(ELF_PYTHON_equality
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_equality.py")

  ADD_PYTHON_TEST(ELF_PYTHON_core
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_core.py")


  # Examples
  # --------
  ADD_PYTHON_TEST(EXAMPLE_PYTHON_elf_reader_ls
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/elf_reader.py --all \
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_ls.bin")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_elf_reader_arm
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/elf_reader.py --all \
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_ARM_binary_ls.bin")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_elf_remove_sections_table
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/elf_remove_section_table.py \
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_ls.bin \
    ${CMAKE_CURRENT_BINARY_DIR}/ls_without_sections")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_elf_symbol_obfuscation
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/elf_symbol_obfuscation.py \
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_x86_binary_ls.bin \
    ${CMAKE_CURRENT_BINARY_DIR}/ls_symbol_obfuscated")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_elf_unstrip
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/elf_unstrip.py \
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_ls.bin \
    ${CMAKE_CURRENT_BINARY_DIR}/ls_unstriped")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_elf_json
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/elf_json.py \
    ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_ls.bin")
endif()
