find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)

if (LIEF_PY_LIEF_EXT)
  find_package(LIEF REQUIRED COMPONENTS STATIC)
  message(STATUS "Using pre-installed version of LIEF")
  set(LIEF_TARGET LIEF::LIEF)
else()
  set(LIEF_TARGET LIB_LIEF)
endif()

include(FetchContent)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()


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

if (LIEF_EXTERNAL_NANOBINDS)
  find_package(nanobind REQUIRED)
else()
  set(NANOBIND_VERSION 1.6.2.r20.g46ed29e)
  set(NANOBIND_SHA256 SHA256=fd91abf745de6b67edf87f9549df5380b666a66218b0bf170e27313d3a726ee7)
  set(NANOBIND_URL "${THIRD_PARTY_DIRECTORY}/nanobind-${NANOBIND_VERSION}.zip" CACHE STRING "URL to the Nanobind")
  FetchContent_Declare(nanobind
    URL        ${NANOBIND_URL}
    URL_HASH   ${NANOBIND_SHA256}
  )
  FetchContent_Populate(nanobind)
  find_package(nanobind REQUIRED PATHS ${nanobind_SOURCE_DIR}/cmake NO_DEFAULT_PATH)
endif()

message(STATUS "Python version:     ${Python_VERSION}")
message(STATUS "Python lib:         ${Python_LIBRARIES}")
message(STATUS "Python include:     ${Python_INCLUDE_DIRS}")
message(STATUS "Python interpreter: ${Python_EXECUTABLE}")

set(LIEF_PYTHON_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pyLIEF.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pySafeString.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pyErr.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pyIOStream.cpp"
)

set(LIEF_PYTHON_HDR
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pyLIEF.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pyErr.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/pySafeString.hpp"
)

nanobind_add_module(
  pyLIEF
  NB_STATIC

  ${LIEF_PYTHON_SRC}
  ${LIEF_PYTHON_HDR}

  # Do not default to -Os
  NOMINSIZE
)

target_include_directories(pyLIEF PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

add_subdirectory(src/Abstract)
add_subdirectory(src/platforms)

if(LIEF_ELF)
  add_subdirectory(src/ELF)
endif()

if(LIEF_PE)
  add_subdirectory(src/PE)
endif()

if(LIEF_MACHO)
  add_subdirectory(src/MachO)
endif()

if(LIEF_OAT)
  add_subdirectory(src/OAT)
endif()

if(LIEF_DEX)
  add_subdirectory(src/DEX)
endif()

if(LIEF_VDEX)
  add_subdirectory(src/VDEX)
endif()

if(LIEF_ART)
  add_subdirectory(src/ART)
endif()

set_target_properties(pyLIEF PROPERTIES
  POSITION_INDEPENDENT_CODE    ON
  CXX_STANDARD                 17
  CXX_STANDARD_REQUIRED        ON
  CXX_VISIBILITY_PRESET        hidden
  C_VISIBILITY_PRESET          hidden
  PREFIX                       ""
  OUTPUT_NAME                  "lief"
)

set_target_properties(pyLIEF PROPERTIES PYTHON_VERSION ${Python_VERSION})
target_link_libraries(pyLIEF PUBLIC ${LIEF_TARGET} lief_spdlog)

if(APPLE)
  set_target_properties(pyLIEF PROPERTIES
    MACOSX_RPATH     ON
    LINK_FLAGS       "-undefined dynamic_lookup "
  )
endif()

set_target_properties(pyLIEF PROPERTIES PREFIX "")
if (UNIX)
  # Even on osx (c.f. EXT_SUFFIX from sysconfig)
  set_target_properties(pyLIEF PROPERTIES SUFFIX ".so")
elseif(WIN32)
  set_target_properties(pyLIEF PROPERTIES SUFFIX ".pyd")
endif()

get_target_property(suffix pyLIEF SUFFIX)
set(LIEF_LIBRARY_NAME "lief${suffix}")

if (WIN32)
  target_link_libraries(pyLIEF PUBLIC ${PYTHON_LIBRARIES})
endif()

if (CMAKE_BUILD_TYPE MATCHES Release AND UNIX AND NOT APPLE)
  add_custom_command(TARGET pyLIEF
    COMMENT "Strip LIEF Python bindings"
    POST_BUILD
    COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:pyLIEF>
  )
endif()

if (CMAKE_BUILD_TYPE MATCHES Release AND APPLE)
  add_custom_command(TARGET pyLIEF
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

