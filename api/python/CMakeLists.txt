cmake_minimum_required(VERSION 3.1)
include(ExternalProject)
include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)


set(Python_ADDITIONAL_VERSIONS 2.7 2.7.6 3.4 3.5 3.6 3.7)
if (NOT ${PYTHON_VERSION} STREQUAL "")
  find_package(PythonLibs ${PYTHON_VERSION} EXACT)

  if (NOT PythonLibs_FOUND)
    find_package(PythonLibs ${PYTHON_VERSION})
  endif()

  set(PYTHONLIBS_VERSION_STRING "${PYTHON_VERSION}")
  if (NOT PythonLibs_FOUND)
    # WARNING: DIRTY HACK
    # ^^^^^^^^^^^^^^^^^^^
    if ((${PYTHON_VERSION} VERSION_GREATER "3") OR (${PYTHON_VERSION} VERSION_EQUAL "3"))
      if (UNIX)
        set(PYTHON_LIBRARY /usr/lib/libpython${PYTHON_VERSION}.so)
        if(EXISTS "/usr/include/python${PYTHON_VERSION}" AND IS_DIRECTORY "/usr/include/python${PYTHON_VERSION}")
          set(PYTHON_INCLUDE_DIR /usr/include/python${PYTHON_VERSION})
          set(PYTHONLIBS_VERSION_STRING "${PYTHON_VERSION}")
        elseif(EXISTS "/usr/include/python${PYTHON_VERSION}m" AND IS_DIRECTORY "/usr/include/python${PYTHON_VERSION}m")
          set(PYTHON_INCLUDE_DIR /usr/include/python${PYTHON_VERSION}m)
          set(PYTHONLIBS_VERSION_STRING "${PYTHON_VERSION}m")
        endif()
      endif()
    endif()
  endif()
else()
  find_package(PythonLibs REQUIRED)
endif()


message(STATUS "Python version: ${PYTHONLIBS_VERSION_STRING}")
message(STATUS "Python lib:     ${PYTHON_LIBRARY}")
message(STATUS "Python include: ${PYTHON_INCLUDE_DIR}")

set(PYBIND11_VERSION v2.2.1)
set(PYBIND11_URL "https://github.com/pybind/pybind11/archive/${PYBIND11_VERSION}.zip" CACHE STRING "URL to the Pybind11 repo")
ExternalProject_Add(lief_pybind11
  URL               ${PYBIND11_URL}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   "")
ExternalProject_get_property(lief_pybind11 SOURCE_DIR)
set(PYBIND11_SOURCE_DIR "${SOURCE_DIR}")


# Define source files
set(LIEF_PYTHON_BASIC_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLIEF.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyUtils.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyIterators.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyExceptions.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLogger.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/encoding.cpp"
)

if (LIEF_ENABLE_JSON)
  set(LIEF_PYTHON_BASIC_SRC
    ${LIEF_PYTHON_BASIC_SRC}
    "${CMAKE_CURRENT_SOURCE_DIR}/pyJson.cpp"
  )
endif()

set(LIEF_PYTHON_SRC
  ${LIEF_PYTHON_BASIC_SRC}
)


set(LIEF_PYTHON_BASIC_HDR
  "${CMAKE_CURRENT_SOURCE_DIR}/pyIterators.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLIEF.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/encoding.hpp"
)

set(LIEF_PYTHON_HDR
  ${LIEF_PYTHON_BASIC_HDR}
)

source_group("Header Files" FILES ${LIEF_PYTHON_BASIC_HDR})

add_library(pyLIEF SHARED ${LIEF_PYTHON_SRC} ${LIEF_PYTHON_HDR})

target_include_directories(pyLIEF PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/"
  "${PYTHON_INCLUDE_DIR}"
  "${PYBIND11_SOURCE_DIR}/include")

add_definitions(-DELPP_NO_DEFAULT_LOG_FILE)

include("${CMAKE_CURRENT_SOURCE_DIR}/Abstract/CMakeLists.txt")

if(LIEF_ELF)
  include("${CMAKE_CURRENT_SOURCE_DIR}/ELF/CMakeLists.txt")
endif()

if(LIEF_PE)
  include("${CMAKE_CURRENT_SOURCE_DIR}/PE/CMakeLists.txt")
endif()

if(LIEF_MACHO)
  include("${CMAKE_CURRENT_SOURCE_DIR}/MachO/CMakeLists.txt")
endif()


target_compile_features(pyLIEF PRIVATE cxx_attribute_deprecated)

set_property(TARGET pyLIEF PROPERTY CXX_STANDARD          11)
set_property(TARGET pyLIEF PROPERTY CXX_STANDARD_REQUIRED ON)

if (MSVC)
  target_compile_options(pyLIEF PUBLIC /FIiso646.h)
	set_property(TARGET pyLIEF PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

set_target_properties(pyLIEF PROPERTIES PYTHON_VERSION ${PYTHONLIBS_VERSION_STRING})
set(PYLIEF_DEPS_LIBRARIES LIB_LIEF_STATIC)

if(LIEF_COVERAGE)
  target_compile_options(pyLIEF PRIVATE -g -O0 --coverage -fprofile-arcs -ftest-coverage)
  set(PYLIEF_DEPS_LIBRARIES ${PYLIEF_DEPS_LIBRARIES} gcov)
endif()

set(PYLIEF_COMPILE_FLAGS)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  CHECK_CXX_COMPILER_FLAG("-Wno-macro-redefined" HAS_NO_MACRO_REDEFINED)
  set(PYLIEF_COMPILE_FLAGS ${PYLIEF_COMPILE_FLAGS} -Wall -Wextra -Wpedantic)
  if (HAS_NO_MACRO_REDEFINED)
    set(PYLIEF_COMPILE_FLAGS ${PYLIEF_COMPILE_FLAGS} -Wno-macro-redefined)
  endif()

  target_compile_options(pyLIEF PRIVATE ${PYLIEF_COMPILE_FLAGS})
endif()

set_target_properties(pyLIEF PROPERTIES PREFIX "" OUTPUT_NAME "_pylief")
add_dependencies(pyLIEF lief_pybind11)

if(APPLE)
    set_target_properties(pyLIEF PROPERTIES MACOSX_RPATH ".")
    set_target_properties(pyLIEF PROPERTIES LINK_FLAGS "-undefined dynamic_lookup ")
endif()

set_target_properties(pyLIEF PROPERTIES PREFIX "")
if (UNIX)
  set_target_properties(pyLIEF PROPERTIES SUFFIX ".so")
elseif(WIN32)
  set_target_properties(pyLIEF PROPERTIES SUFFIX ".pyd")
endif()

get_target_property(suffix pyLIEF SUFFIX)
set(LIEF_LIBRARY_NAME "lief${suffix}")

if (WIN32)
  set(PYLIEF_DEPS_LIBRARIES ${PYLIEF_DEPS_LIBRARIES} ${PYTHON_LIBRARIES})
endif()

target_link_libraries(pyLIEF PUBLIC ${PYLIEF_DEPS_LIBRARIES})

add_custom_command(TARGET pyLIEF POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pyLIEF> ${PROJECT_BINARY_DIR}/api/python/lief
)

if (MSVC)
  add_custom_command(TARGET pyLIEF POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pyLIEF> ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in"    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/__init__.py.in" "${CMAKE_CURRENT_BINARY_DIR}/lief/__init__.py")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/README"         "${CMAKE_CURRENT_BINARY_DIR}/README")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/MANIFEST.in"    "${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.in")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/setup.cfg"      "${CMAKE_CURRENT_BINARY_DIR}/setup.cfg")

MESSAGE(STATUS "OS: ${CMAKE_HOST_SYSTEM}")

find_program(ENV_BINARY "env")

if (UNIX AND ENV_BINARY AND LIEF_INSTALL_PYTHON)
  if ((${PYTHONLIBS_VERSION_STRING} VERSION_GREATER "3") OR (${PYTHONLIBS_VERSION_STRING} VERSION_EQUAL "3"))
    install(CODE "execute_process(COMMAND ${ENV_BINARY} python3 ${CMAKE_CURRENT_BINARY_DIR}/setup.py install)"
      COMPONENT python)
  else()
    install(
      CODE "execute_process(COMMAND ${ENV_BINARY} python2 ${CMAKE_CURRENT_BINARY_DIR}/setup.py install)"
      COMPONENT python)
  endif()
endif()


