cmake_minimum_required(VERSION 3.1)
include(ExternalProject)

# Examples tests
# ==============
if (LIEF_EXAMPLES)

  file(GLOB_RECURSE SAMPLES_PE
    "${LIEF_SAMPLES_DIRECTORY}/PE/*.exe"
    "${LIEF_SAMPLES_DIRECTORY}/PE/*.dll")

  foreach(PE_PATH ${SAMPLES_PE})
    get_filename_component(PE_NAME ${PE_PATH} NAME)
    # PE Reader
    add_test(
      NAME EXAMPLES_CPP_pe_reader_${PE_NAME}
      COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/cpp/pe_reader
      ${PE_PATH})

    if (LIEF_C_API)
      add_test(
        NAME EXAMPLES_C_pe_reader_${PE_NAME}
        COMMAND ${LIEF_EXAMPLES_BINARY_DIR}/c/pe_reader
        ${PE_PATH})
    endif()


    if (PYTHON_TESTS_ENABLED)

      ADD_PYTHON_TEST(EXAMPLE_PYTHON_pe_reader_${PE_NAME}
        ${PYTHON_EXECUTABLE}
        "${LIEF_EXAMPLES_DIRECTORY}/python/pe_reader.py --all \
        ${PE_PATH}")
    endif()
  endforeach()
endif()

# Python tests
# ============
if (PYTHON_TESTS_ENABLED)

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_pe_reader_kernel32
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/pe_reader.py \
    ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86_library_kernel32.dll")

  ADD_PYTHON_TEST(PE_PYTHON_pe
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_pe.py")

  ADD_PYTHON_TEST(PE_PYTHON_hooking
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_hooking.py")

  ADD_PYTHON_TEST(PE_PYTHON_resources
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_resources.py")

  ADD_PYTHON_TEST(PE_PYTHON_imphash
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_imphash.py")

  ADD_PYTHON_TEST(PE_PYTHON_builder
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_builder.py")

  ADD_PYTHON_TEST(PE_PYTHON_load_configuration
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_loadconfig.py")

  ADD_PYTHON_TEST(PE_PYTHON_forwarded_exports
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_forward_information.py")

  ADD_PYTHON_TEST(PE_PYTHON_authenticode
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_authenticode.py")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_pe_authenticode_reader
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/authenticode/authenticode_reader.py \
    --all --crt --hash --check --allow-expired --save test.p7b \
    ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe")

  ADD_PYTHON_TEST(EXAMPLE_PYTHON_pe_authenticode_api
    ${PYTHON_EXECUTABLE}
    "${LIEF_EXAMPLES_DIRECTORY}/python/authenticode/api_example.py \
    ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe")

endif()


