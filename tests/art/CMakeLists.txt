cmake_minimum_required(VERSION 3.1)
include(ExternalProject)

macro(ADD_ART_TEST name sources)

  add_executable(${name}        ${sources} ${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp)
  add_executable(${name}_shared ${sources} ${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp)

  set_property(TARGET ${name} ${name}_shared PROPERTY INCLUDE_DIRECTORIES "")

  if (MSVC)
    target_compile_options(${name}        PUBLIC /FIiso646.h)
    target_compile_options(${name}_shared PUBLIC /FIiso646.h)

	  target_compile_options(${name}_shared PUBLIC /MT)
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


# Python tests
# ============
if (PYTHON_TESTS_ENABLED)


  # Unit tests
  # ----------
  ADD_PYTHON_TEST(UNITTEST_PYTHON_art
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/art_test.py")

endif()
