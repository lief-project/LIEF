cmake_minimum_required(VERSION 3.1)
include(ExternalProject)

macro(ADD_ELF_TEST name sources)

  add_executable(${name}        ${sources} ${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp)
  add_executable(${name}_shared ${sources} ${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp)

  set_property(TARGET ${name} ${name}_shared PROPERTY INCLUDE_DIRECTORIES "")

  if (MSVC)
    target_compile_options(${name}        PUBLIC /FIiso646.h)
    target_compile_options(${name}_shared PUBLIC /FIiso646.h)

    if (CMAKE_BUILD_TYPE MATCHES "Debug")
      target_compile_options("${name}_shared" PUBLIC /MTd)
    else()
      target_compile_options("${name}_shared" PUBLIC /MT)
    endif()

	  set_property(TARGET ${name} ${name}_shared PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
  endif()

  set_property(TARGET ${name} PROPERTY CXX_STANDARD          11)
  set_property(TARGET ${name} PROPERTY CXX_STANDARD_REQUIRED ON)

  set_property(TARGET ${name}_shared PROPERTY CXX_STANDARD          11)
  set_property(TARGET ${name}_shared PROPERTY CXX_STANDARD_REQUIRED ON)


  target_include_directories(${name} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${YAMLCPP_INCLUDE_DIRS}
    ${DIRENT_INCLUDE_DIR}
    ${CATCH_INCLUDE_DIR})

  target_include_directories(${name}_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${YAMLCPP_INCLUDE_DIRS}
    ${DIRENT_INCLUDE_DIR}
    ${CATCH_INCLUDE_DIR})

  add_dependencies(${name}        catch YAMLCPP)
  add_dependencies(${name}_shared catch YAMLCPP)

  if (WIN32)
    add_dependencies(${name}        dirent)
    add_dependencies(${name}_shared dirent)
  endif()

  target_link_libraries(${name}        PUBLIC LIB_LIEF_STATIC ${YAMLCPP_LIBRARY_RELEASE})
  target_link_libraries(${name}_shared PUBLIC LIB_LIEF_SHARED ${YAMLCPP_LIBRARY_RELEASE})

  if (LIEF_TEST_STATIC)
    add_test(${name}         ${CMAKE_CURRENT_BINARY_DIR}/${name})
  endif()

  if (LIEF_TEST_SHARED)
    add_test(${name}_shared  ${CMAKE_CURRENT_BINARY_DIR}/${name}_shared)
  endif()

endmacro()


# Targets
# =======

set(test_parser_sources
  ${CMAKE_CURRENT_SOURCE_DIR}/test_parser.cpp)

set(test_equality_sources
  ${CMAKE_CURRENT_SOURCE_DIR}/test_equality.cpp)

set(test_builder_sources
  ${CMAKE_CURRENT_SOURCE_DIR}/test_builder.cpp)

set(test_modifier_sources
  ${CMAKE_CURRENT_SOURCE_DIR}/test_modifier.cpp)


ADD_ELF_TEST(elf_test_parser   ${test_parser_sources})
ADD_ELF_TEST(elf_test_equality ${test_equality_sources})
ADD_ELF_TEST(elf_test_builder  ${test_builder_sources})
ADD_ELF_TEST(elf_test_modifier ${test_modifier_sources})

# Examples tests
# ==============
if (LIEF_EXAMPLES)
  file(GLOB_RECURSE SAMPLES_ELF
    "${LIEF_SAMPLES_DIRECTORY}/ELF/*.bin"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/*.so"
    "${LIEF_SAMPLES_DIRECTORY}/ELF/*.pie"
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
