cmake_minimum_required(VERSION 3.1)
include(ExternalProject)

macro(ADD_PE_TEST name sources)

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
    ${DIRENT_INCLUDE_DIR}
    ${YAMLCPP_INCLUDE_DIRS}
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
    add_test(${name} ${CMAKE_CURRENT_BINARY_DIR}/${name})
  endif()

  if (LIEF_TEST_SHARED)
    add_test(${name}_shared ${CMAKE_CURRENT_BINARY_DIR}/${name}_shared)
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


set(test_binary_sources
  ${CMAKE_CURRENT_SOURCE_DIR}/test_binary.cpp)

ADD_PE_TEST(pe_test_parser   ${test_parser_sources})
ADD_PE_TEST(pe_test_equality ${test_equality_sources})
ADD_PE_TEST(pe_test_builder  ${test_builder_sources})
ADD_PE_TEST(pe_test_binary   ${test_binary_sources})



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
# ============
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

endif()


