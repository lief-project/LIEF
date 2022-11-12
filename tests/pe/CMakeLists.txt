if (LIEF_EXAMPLES)
  file(GLOB_RECURSE SAMPLES_PE
       "${LIEF_SAMPLES_DIRECTORY}/PE/*.exe"
       "${LIEF_SAMPLES_DIRECTORY}/PE/*.dll")

  foreach(PE_PATH ${SAMPLES_PE})
    get_filename_component(PE_NAME ${PE_PATH} NAME)
    add_test(EXAMPLES_CPP_pe_reader_${PE_NAME}
             ${LIEF_EXAMPLES_BINARY_DIR}/cpp/pe_reader ${PE_PATH})

    if (LIEF_C_API)
      add_test(EXAMPLES_C_pe_reader_${PE_NAME}
               ${LIEF_EXAMPLES_BINARY_DIR}/c/pe_reader ${PE_PATH})
    endif()

    if (PYTHON_TESTS_ENABLED)
      add_test(EXAMPLE_PYTHON_pe_reader_${PE_NAME}
               ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
               ${PYTHON_EXECUTABLE}
                 ${LIEF_EXAMPLES_DIRECTORY}/python/pe_reader.py --all ${PE_PATH})
    endif()
  endforeach()
endif()

if (PYTHON_TESTS_ENABLED)
  add_test(PE_PYTHON_tests
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE} -m pytest -rA ${CMAKE_CURRENT_SOURCE_DIR})

  add_test(EXAMPLE_PYTHON_pe_reader_kernel32
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE}
      ${LIEF_EXAMPLES_DIRECTORY}/python/pe_reader.py
      ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86_library_kernel32.dll)

  add_test(EXAMPLE_PYTHON_pe_authenticode_reader
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE}
    ${LIEF_EXAMPLES_DIRECTORY}/python/authenticode/authenticode_reader.py
      --all --crt --hash --check --allow-expired --save test.p7b
      ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe)

  add_test(EXAMPLE_PYTHON_pe_authenticode_api
    ${CMAKE_COMMAND} -E env "PYTHONPATH=${PYTHONENV}"
    ${PYTHON_EXECUTABLE}
      ${LIEF_EXAMPLES_DIRECTORY}/python/authenticode/api_example.py
      ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe)

endif()


