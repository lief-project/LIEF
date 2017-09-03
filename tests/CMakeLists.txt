find_package(Git REQUIRED)
enable_testing()

option(LIEF_TEST_SHARED "Test LIEF using the SHARED library" ON)
option(LIEF_TEST_STATIC "Test LIEF using the STATIC library" ON)

# Tests samples
# =============
set(SAMPLES_GIT_URL "https://github.com/lief-project/samples.git" CACHE STRING "URL to tests samples")
set(SAMPLES_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/lief-samples")
set(SAMPLES_TAG master)

ExternalProject_Add(lief_samples
  PREFIX            ${SAMPLES_PREFIX}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
  GIT_REPOSITORY    ${SAMPLES_GIT_URL}
  GIT_TAG           ${SAMPLES_TAG}
  UPDATE_COMMAND    ${GIT_EXECUTABLE} pull
)

ExternalProject_Get_Property(lief_samples source_dir)
set(LIEF_SAMPLES_DIRECTORY "${source_dir}" CACHE INTERNAL "Path to LIEF samples")
message(STATUS "Samples directory: ${LIEF_SAMPLES_DIRECTORY}")

# Tests options
# =============
option(LIEF_FUZZING "Fuzz LIEF" OFF)

if (NOT LIEF_ELF OR NOT LIEF_PE OR NOT LIEF_MACHO)
  message(FATAL_ERROR "Tests require all LIEF's modules activated" )
endif()

set(LIEF_EXAMPLES_DIRECTORY  "${PROJECT_SOURCE_DIR}/examples")
set(LIEF_EXAMPLES_BINARY_DIR "${PROJECT_BINARY_DIR}/examples")
#set(LIEF_SAMPLES_DIRECTORY   "${CMAKE_CURRENT_SOURCE_DIR}/samples")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.yaml.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.yaml"
  @ONLY)


if (MSVC)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/utils.py.in"
    "${PROJECT_BINARY_DIR}/api/python/utils.py"
    @ONLY)
else()
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/utils.py.in"
    "${PROJECT_BINARY_DIR}/api/python/utils.py"
    @ONLY)
endif()

add_definitions(-DPATH_TO_CONFIG="${CMAKE_CURRENT_BINARY_DIR}")
add_definitions(-DPATH_TO_SAMPLES="${LIEF_SAMPLES_DIRECTORY}")


# YAML CPP
# ========
set(YAMLCPP_PREFIX      "${CMAKE_CURRENT_BINARY_DIR}/YAMLCPP")
set(YAMLCPP_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/YAMLCPP")

set(
  YAMLCPP_CMAKE_ARGS
  -DCMAKE_INSTALL_PREFIX=${YAMLCPP_INSTALL_DIR}
  -DCMAKE_BUILD_TYPE=Release
  -DYAML_CPP_BUILD_TOOLS=off
  -DYAML_CPP_BUILD_CONTRIB=off
  )

if(LIEF_FORCE32)
  set(YAMLCPP_CMAKE_ARGS ${YAMLCPP_CMAKE_ARGS}
    -DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS} -m32"
    -DCMAKE_C_FLAGS="${CMAKE_C_FLAGS} -m32")
endif()


if (WIN32)
set(CXX_FLAGS "/MT /EHsc")
  set(YAMLCPP_CMAKE_ARGS ${YAMLCPP_CMAKE_ARGS} -DCMAKE_CXX_FLAGS=${CXX_FLAGS} )
endif()

set(YAMLCPP_GIT_URL "https://github.com/jbeder/yaml-cpp.git" CACHE STRING "URL to the YAMLCPP repo")

ExternalProject_Add(YAMLCPP
  PREFIX         ${YAMLCPP_PREFIX}
  GIT_REPOSITORY ${YAMLCPP_GIT_URL}
  GIT_TAG        beb44b872c07c74556314e730c6f20a00b32e8e5
  INSTALL_DIR    ${YAMLCPP_INSTALL_DIR}
  CMAKE_ARGS     ${YAMLCPP_CMAKE_ARGS}
  LOG_DOWNLOAD ON
  )

set(YAMLCPP_INCLUDE_DIRS "${YAMLCPP_INSTALL_DIR}/include")
if(WIN32)
  set(YAMLCPP_LIBRARY_RELEASE "${YAMLCPP_INSTALL_DIR}/lib/libyaml-cppmd${CMAKE_STATIC_LIBRARY_SUFFIX}")
else()
  set(YAMLCPP_LIBRARY_RELEASE "${YAMLCPP_INSTALL_DIR}/lib/libyaml-cpp${CMAKE_STATIC_LIBRARY_SUFFIX}")
endif()

# Catch
# =====

set(CATCH_PREFIX  "${CMAKE_CURRENT_BINARY_DIR}/catch")
set(CATCH_GIT_URL https://github.com/philsquared/Catch.git CACHE STRING "URL to the Catch repo")

ExternalProject_Add(catch
    PREFIX         ${CATCH_PREFIX}
    GIT_REPOSITORY ${CATCH_GIT_URL}
    GIT_TAG        "v1.10.0"
    TIMEOUT 10
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
    LOG_DOWNLOAD ON
)
ExternalProject_Get_Property(catch source_dir)
set(CATCH_INCLUDE_DIR "${source_dir}/include" CACHE INTERNAL "Path to include folder for Catch")


# Dirent
# ======
set(DIRENT_INCLUDE_DIR "")
if (WIN32)
  set(DIRENT_PREFIX  "${CMAKE_CURRENT_BINARY_DIR}/dirent")
  set(DIRENT_GIT_URL https://github.com/tronkko/dirent.git CACHE STRING "URL to the dirent repo")

  ExternalProject_Add(dirent
      PREFIX         ${DIRENT_PREFIX}
      GIT_REPOSITORY ${DIRENT_GIT_URL}
      GIT_TAG        "1.22"
      TIMEOUT 10
      CONFIGURE_COMMAND ""
      BUILD_COMMAND ""
      INSTALL_COMMAND ""
      LOG_DOWNLOAD ON
  )

  ExternalProject_Get_Property(dirent source_dir)
  set(DIRENT_INCLUDE_DIR "${source_dir}/include" CACHE INTERNAL "Path to include folder for dirent")
endif()




# Code covergage
# ==============
if(LIEF_COVERAGE)
  find_program(GCOV_PATH gcov)
  find_program(LCOV_PATH lcov)
  find_program(GENHTML_PATH genhtml)
  find_program(GCOVR_PATH gcovr PATHS ${CMAKE_SOURCE_DIR}/tests)

  set(output_name "lief_coverage")
	set(coverage_info "${CMAKE_BINARY_DIR}/${output_name}.info")
	set(coverage_cleaned "${coverage_info}.cleaned")

  add_custom_target(lief_coverage

		# Cleanup lcov
		${LCOV_PATH} --zerocounters --directory .

		# Run tests
    COMMAND make check-lief
    #COMMAND ctest -R test_iterators

		# Capturing lcov counters and generating report
		COMMAND ${LCOV_PATH} --directory . --capture --output-file ${coverage_info}
    COMMAND ${LCOV_PATH} --remove ${coverage_info} 'utf8/*' 'filesystem/*' 'libjson/*' 'tests/*' '/usr/*' 'pybind11/*' '*mbedtls*' rang_cpp_color/* easyloggingpp/* -output-file ${coverage_cleaned}
		COMMAND ${GENHTML_PATH} -o ${output_name} ${coverage_cleaned}
    #COMMAND ${CMAKE_COMMAND} -E remove ${coverage_info} ${coverage_cleaned}

		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
	)

endif()


# Fuzzing
# =======
if(UNIX AND NOT APPLE)
  set(MELKOR_REPO "https://github.com/IOActive/Melkor_ELF_Fuzzer.git")

  set(MELKOR_PREFIX      "${CMAKE_CURRENT_BINARY_DIR}/Melkor")
  set(MELKOR_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/Melkor")
  ExternalProject_Add(MELKOR
   PREFIX            ${MELKOR_PREFIX}
   GIT_REPOSITORY    ${MELKOR_REPO}
   INSTALL_DIR       ${MELKOR_INSTALL_DIR}
   UPDATE_COMMAND    ""
   CONFIGURE_COMMAND ""
   INSTALL_COMMAND   ""
   BUILD_COMMAND     make clean && make
   BUILD_IN_SOURCE   ON)

  ExternalProject_get_property(MELKOR SOURCE_DIR)
  set(MELKOR_BINARY "${SOURCE_DIR}/melkor")
  message(STATUS "${MELKOR_BINARY}")
endif()

# Tests
# =====
add_executable(test_iterators "${CMAKE_CURRENT_SOURCE_DIR}/test_iterators.cpp")

if (MSVC)
  target_compile_options(test_iterators PUBLIC /FIiso646.h)
  set_property(TARGET test_iterators PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

set_property(TARGET test_iterators PROPERTY CXX_STANDARD          11)
set_property(TARGET test_iterators PROPERTY CXX_STANDARD_REQUIRED ON)

target_include_directories(test_iterators PUBLIC
  $<TARGET_PROPERTY:LIB_LIEF_STATIC,INCLUDE_DIRECTORIES>
  ${CATCH_INCLUDE_DIR})

if (LIEF_COVERAGE)
  target_compile_options(test_iterators PRIVATE -g -O0 --coverage -fprofile-arcs -ftest-coverage)
  target_link_libraries(test_iterators gcov)
endif()

add_dependencies(test_iterators catch LIB_LIEF_STATIC)

target_link_libraries(test_iterators LIB_LIEF_STATIC)

add_test(test_iterators ${CMAKE_CURRENT_BINARY_DIR}/test_iterators)

# Python
# ======
if(WIN32)
  configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/run_python_test.bat.in"
  "${CMAKE_CURRENT_BINARY_DIR}/run_python_test.bat"
  @ONLY)
endif()

macro(ADD_PYTHON_TEST name command)
if(UNIX)
	add_test(${name}
      "bash"
      "-c"
      "PYTHONPATH=\"${PROJECT_BINARY_DIR}/api/python\" ${command} ${ARGN}")
endif()

if(WIN32)
   add_test(${name}
      "${PROJECT_BINARY_DIR}/tests/run_python_test.bat"
	  "${command}"
	  "${ARGN}")
endif()
endmacro()

if (LIEF_PYTHON_API)
  set(PYTHON_TESTS_ENABLED OFF)
  get_target_property(PYTHON_VERSION pyLIEF PYTHON_VERSION)
  if ((${PYTHON_VERSION} VERSION_GREATER "3") OR (${PYTHON_VERSION} VERSION_EQUAL "3"))

    find_package(PythonInterp 3)
    if (NOT PythonInterp_FOUND)
      string(REPLACE "m" "" PYTHON_VERSION_CLEAN ${PYTHON_VERSION})
      set(PYTHON_EXECUTABLE "/usr/bin/python${PYTHON_VERSION_CLEAN}")
    endif()

  else()
    find_package(PythonInterp 2 REQUIRED)
  endif()

  message(STATUS "Python executable: ${PYTHON_EXECUTABLE}")

  if (PYTHONINTERP_FOUND)
    set(PYTHON_TESTS_ENABLED ON)
  endif()

  if (PYTHON_TESTS_ENABLED)

    # nm
    # --
    ADD_PYTHON_TEST(EXAMPLE_PYTHON_nm_elf
      ${PYTHON_EXECUTABLE}
      "${LIEF_EXAMPLES_DIRECTORY}/python/nm.py \
      ${LIEF_SAMPLES_DIRECTORY}/MachO/MachO64_x86-64_binary_ls.bin")

    ADD_PYTHON_TEST(EXAMPLE_PYTHON_nm_pe
      ${PYTHON_EXECUTABLE}
      "${LIEF_EXAMPLES_DIRECTORY}/python/nm.py \
      ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86_binary_winhello-mingw.exe")

    ADD_PYTHON_TEST(EXAMPLE_PYTHON_nm_macho
      ${PYTHON_EXECUTABLE}
      "${LIEF_EXAMPLES_DIRECTORY}/python/nm.py \
      ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_ARM_binary_ls.bin")

    # Abstract
    # --------
    ADD_PYTHON_TEST(EXAMPLE_PYTHON_abstract_reader_pe
      ${PYTHON_EXECUTABLE}
      "${LIEF_EXAMPLES_DIRECTORY}/python/abstract_reader.py \
      ${LIEF_SAMPLES_DIRECTORY}/PE/PE32_x86_binary_cmd-upx.exe")

    ADD_PYTHON_TEST(EXAMPLE_PYTHON_abstract_reader_elf
      ${PYTHON_EXECUTABLE}
      "${LIEF_EXAMPLES_DIRECTORY}/python/abstract_reader.py \
      ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF32_ARM_binary_ls.bin")

    ADD_PYTHON_TEST(EXAMPLE_PYTHON_abstract_reader_macho
      ${PYTHON_EXECUTABLE}
      "${LIEF_EXAMPLES_DIRECTORY}/python/abstract_reader.py \
      ${LIEF_SAMPLES_DIRECTORY}/MachO/MachO64_x86-64_binary_id.bin")

    ADD_PYTHON_TEST(EXAMPLE_PYTHON_abstract_json
      ${PYTHON_EXECUTABLE}
      "${LIEF_EXAMPLES_DIRECTORY}/python/abstract_json.py \
      ${LIEF_SAMPLES_DIRECTORY}/ELF/ELF64_x86-64_binary_ls.bin")

    ADD_PYTHON_TEST(UNITTEST_PYTHON_abstract
      ${PYTHON_EXECUTABLE}
      "${CMAKE_CURRENT_SOURCE_DIR}/abstract/abstract_tests.py")
  endif()


endif()

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/elf")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/pe")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/macho")

# /!\ Bad Hack /!\
add_dependencies(LIB_LIEF_STATIC lief_samples)
add_dependencies(LIB_LIEF_SHARED lief_samples)

add_custom_target(check-lief COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
  DEPENDS lief_samples)
