cmake_minimum_required(VERSION 3.1)
include(ExternalProject)
include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)


macro(ADD_FLAG_IF_SUPPORTED flag name)
  CHECK_C_COMPILER_FLAG("${flag}"   "C_SUPPORTS_${name}")
  CHECK_CXX_COMPILER_FLAG("${flag}" "CXX_SUPPORTS_${name}")

  if (C_SUPPORTS_${name})
    target_compile_options(pyLIEF PRIVATE ${flag})
  endif()

  if (CXX_SUPPORTS_${name})
    target_compile_options(pyLIEF PRIVATE ${flag})
  endif()
endmacro()

set(PYTHON_VERSION "3.5" CACHE STRING "Python Version to use")
find_package(PythonLibsNew EXACT ${PYTHON_VERSION} MODULE REQUIRED)

message(STATUS "Python version: ${PYTHON_VERSION}")
message(STATUS "Python lib:     ${PYTHON_LIBRARY}")
message(STATUS "Python include: ${PYTHON_INCLUDE_DIR}")
message(STATUS "Python interpreter: ${PYTHON_EXECUTABLE}")

set(PYBIND11_VERSION 2.6.1)
set(PYBIND11_SHA256 SHA256=e3f9408fca4e8ebf2d22229d5256adb49098073832aad87f3f6078d91a6942b2)
set(PYBIND11_URL "${THIRD_PARTY_DIRECTORY}/pybind11-${PYBIND11_VERSION}.zip" CACHE STRING "URL to the Pybind11 repo")
ExternalProject_Add(lief_pybind11
  URL               ${PYBIND11_URL}
  URL_HASH          ${PYBIND11_SHA256}
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
  "${CMAKE_CURRENT_SOURCE_DIR}/pyHash.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyObject.cpp"
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
  "${CMAKE_CURRENT_SOURCE_DIR}/enums_wrapper.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/encoding.hpp"
)

set(LIEF_PYTHON_HDR
  ${LIEF_PYTHON_BASIC_HDR}
)

source_group("Header Files" FILES ${LIEF_PYTHON_BASIC_HDR})

add_library(pyLIEF SHARED ${LIEF_PYTHON_SRC} ${LIEF_PYTHON_HDR})

target_include_directories(pyLIEF PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/"
)

target_include_directories(pyLIEF SYSTEM PRIVATE
  "${PYTHON_INCLUDE_DIR}"
  "${PYBIND11_SOURCE_DIR}/include")

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

if(LIEF_OAT)
  include("${CMAKE_CURRENT_SOURCE_DIR}/OAT/CMakeLists.txt")
endif()

if(LIEF_DEX)
  include("${CMAKE_CURRENT_SOURCE_DIR}/DEX/CMakeLists.txt")
endif()

if(LIEF_VDEX)
  include("${CMAKE_CURRENT_SOURCE_DIR}/VDEX/CMakeLists.txt")
endif()

if(LIEF_ART)
  include("${CMAKE_CURRENT_SOURCE_DIR}/ART/CMakeLists.txt")
endif()

include("${CMAKE_CURRENT_SOURCE_DIR}/platforms/CMakeLists.txt")


target_compile_features(pyLIEF PRIVATE cxx_attribute_deprecated)

set_target_properties(pyLIEF PROPERTIES
  POSITION_INDEPENDENT_CODE    ON
  CXX_STANDARD                 11
  CXX_STANDARD_REQUIRED        ON
  CXX_VISIBILITY_PRESET        hidden
  C_VISIBILITY_PRESET          hidden
)

if (MSVC)
  if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(pyLIEF PUBLIC /FIiso646.h)
  endif()
  set_property(TARGET pyLIEF PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

set_target_properties(pyLIEF PROPERTIES PYTHON_VERSION ${PYTHON_VERSION})
set(PYLIEF_DEPS_LIBRARIES LIB_LIEF)

if(LIEF_COVERAGE)
  target_compile_options(pyLIEF PRIVATE -g -O0 --coverage -fprofile-arcs -ftest-coverage)
  set(PYLIEF_DEPS_LIBRARIES ${PYLIEF_DEPS_LIBRARIES} gcov)
endif()


ADD_FLAG_IF_SUPPORTED("-Wno-macro-redefined"         NO_MACRO_REDEFINED)
ADD_FLAG_IF_SUPPORTED("-Wno-deprecated-declarations" NO_DEPRECATED_DECLARATIONS)

set_target_properties(pyLIEF PROPERTIES PREFIX "" OUTPUT_NAME "lief")
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


if (CMAKE_BUILD_TYPE MATCHES Release AND UNIX AND NOT APPLE)
    add_custom_command(
      TARGET pyLIEF
      COMMENT "Strip LIEF Python bindings"
      POST_BUILD
      COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:pyLIEF>
    )
endif()

if (CMAKE_BUILD_TYPE MATCHES Release AND APPLE)
  add_custom_command(
    TARGET pyLIEF
    COMMENT "Strip LIEF Python bindings"
    POST_BUILD
    COMMAND ${CMAKE_STRIP} -x -S $<TARGET_FILE:pyLIEF>
  )
endif()

add_custom_command(TARGET pyLIEF POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pyLIEF> ${PROJECT_BINARY_DIR}/api/python/lief
)

if (MSVC)
  add_custom_command(TARGET pyLIEF POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:pyLIEF> ${CMAKE_CURRENT_BINARY_DIR}
  )
endif()

