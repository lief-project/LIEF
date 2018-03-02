cmake_minimum_required(VERSION 3.1)


# Examples tests
# ==============
if (LIEF_EXAMPLES)
  file(GLOB_RECURSE SAMPLES_MACHO
    "${LIEF_SAMPLES_DIRECTORY}/MachO/*.bin"
    "${LIEF_SAMPLES_DIRECTORY}/MachO/*.dylib"
  )


  foreach(MACHO_PATH ${SAMPLES_MACHO})
    get_filename_component(MACHO_NAME ${MACHO_PATH} NAME)

    if (LIEF_C_API)
      add_test(
        NAME EXAMPLES_C_macho_reader_${MACHO_NAME}
        COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/c/macho_reader
        ${MACHO_PATH})
    endif()

    # MachO Reader
    add_test(
      NAME EXAMPLES_CPP_macho_reader_${MACHO_NAME}
      COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/macho_reader
      ${MACHO_PATH})


    # MachO builder
    #add_test(
    #  NAME EXAMPLES_CPP_macho_builder_${MACHO_NAME}
    #  COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/macho_reader
    #  ${MACHO_PATH})
  endforeach()
endif()

# Python tests
# ============
if (PYTHON_TESTS_ENABLED)

  ADD_PYTHON_TEST(UNITTEST_PYTHON_macho
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/macho_tests.py")

  ADD_PYTHON_TEST(UNITTEST_PYTHON_macho_dyld
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/macho_dyld.py")

  ADD_PYTHON_TEST(UNITTEST_PYTHON_macho_opcodes
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/macho_opcodes.py")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_macho_reader_ls
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/macho_reader.py --all \
    ${LIEF_SAMPLES_DIRECTORY}/MachO/MachO64_x86-64_binary_ls.bin")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_macho_reader_libc
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/macho_reader.py --all \
    ${LIEF_SAMPLES_DIRECTORY}/MachO/FAT_MachO_x86_x86-64_library_libc.dylib")

endif()


