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
      add_test(EXAMPLES_C_macho_reader_${MACHO_NAME}
               ${LIEF_EXAMPLES_BINARY_DIR}/c/macho_reader ${MACHO_PATH})
    endif()

    # MachO Reader
    add_test(EXAMPLES_CPP_macho_reader_${MACHO_NAME}
             ${LIEF_EXAMPLES_BINARY_DIR}/cpp/macho_reader ${MACHO_PATH})
  endforeach()
endif()

add_test(UNITTEST_PYTHON_macho
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE} -m pytest
    ${CMAKE_CURRENT_SOURCE_DIR}/test_generic.py)

add_test(UNITTEST_PYTHON_macho_dyld
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/macho_dyld.py)

add_test(UNITTEST_PYTHON_macho_relocation
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/macho_relocations.py)

add_test(UNITTEST_PYTHON_macho_opcodes
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/macho_opcodes.py)

add_test(UNITTEST_PYTHON_macho_builder
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/macho_builder.py)

add_test(UNITTEST_PYTHON_macho_fat_builder
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/macho_fat_builder.py)

add_test(EXAMPLE_PYTHON_macho_reader_ls
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/macho_reader.py --all
    ${LIEF_SAMPLES_DIRECTORY}/MachO/MachO64_x86-64_binary_ls.bin)

add_test(EXAMPLE_PYTHON_macho_reader_libc
  ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
  ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/macho_reader.py --all
    ${LIEF_SAMPLES_DIRECTORY}/MachO/FAT_MachO_x86_x86-64_library_libc.dylib)



