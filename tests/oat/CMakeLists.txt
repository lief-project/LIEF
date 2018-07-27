cmake_minimum_required(VERSION 3.1)
include(ExternalProject)

macro(ADD_OAT_TEST name sources)

  add_executable(${name}        ${sources} ${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp)

  set_property(TARGET ${name} PROPERTY INCLUDE_DIRECTORIES "")

  if (MSVC)
    target_compile_options(${name}        PUBLIC /FIiso646.h)
	  set_property(TARGET ${name} PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
  endif()

  set_property(TARGET ${name} PROPERTY CXX_STANDARD          11)
  set_property(TARGET ${name} PROPERTY CXX_STANDARD_REQUIRED ON)

  target_include_directories(${name} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${YAMLCPP_INCLUDE_DIRS}
    ${DIRENT_INCLUDE_DIR}
    ${CATCH_INCLUDE_DIR})

  add_dependencies(${name}        catch YAMLCPP)

  if (WIN32)
    add_dependencies(${name}        dirent)
  endif()

  target_link_libraries(${name}        PUBLIC LIB_LIEF ${YAMLCPP_LIBRARY_RELEASE})
  add_test(${name}         ${CMAKE_CURRENT_BINARY_DIR}/${name})

endmacro()


# Python tests
# ============
if (PYTHON_TESTS_ENABLED)


  # Unit tests
  # ----------
  ADD_PYTHON_TEST(UNITTEST_PYTHON_oat
    ${PYTHON_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/oat_test.py")

endif()
