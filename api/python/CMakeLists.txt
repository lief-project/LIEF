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

if (LIEF_EXTERNAL_NANOBINDS)
  find_package(nanobind REQUIRED)
else()
  set(NANOBIND_VERSION 1.7.0.r7.gfd1f04b)
  set(NANOBIND_SHA256 SHA256=c6b1e0459559fc753ec6ef0911744f5fbc5f995e868dcb1ecef8f0c6c3d376d2)
  set(NANOBIND_URL "${THIRD_PARTY_DIRECTORY}/nanobind-${NANOBIND_VERSION}.zip"
      CACHE STRING "URL to the Nanobind")
  FetchContent_Declare(nanobind
    URL        ${NANOBIND_URL}
    URL_HASH   ${NANOBIND_SHA256}
  )
  FetchContent_Populate(nanobind)
  find_package(nanobind REQUIRED PATHS ${nanobind_SOURCE_DIR}/cmake
               NO_DEFAULT_PATH)
endif()

message(STATUS "Python version:     ${Python_VERSION}")
message(STATUS "Python lib:         ${Python_LIBRARIES}")
message(STATUS "Python include:     ${Python_INCLUDE_DIRS}")
message(STATUS "Python interpreter: ${Python_EXECUTABLE}")

nanobind_add_module(
  pyLIEF
  NB_STATIC
  # Do not default to -Os
  NOMINSIZE

  src/pyLIEF.cpp
)

add_subdirectory(src)

set_target_properties(pyLIEF PROPERTIES
  POSITION_INDEPENDENT_CODE    ON
  CXX_STANDARD                 17
  CXX_STANDARD_REQUIRED        ON
  CXX_VISIBILITY_PRESET        hidden
  C_VISIBILITY_PRESET          hidden
  PREFIX                       ""
  OUTPUT_NAME                  "_lief"
)

target_link_libraries(pyLIEF PUBLIC ${LIEF_TARGET} lief_spdlog)

if(APPLE)
  set_target_properties(pyLIEF PROPERTIES
    MACOSX_RPATH ON
    LINK_FLAGS   "-undefined dynamic_lookup "
  )
endif()

if (UNIX)
  # Even on osx (c.f. EXT_SUFFIX from sysconfig)
  set_target_properties(pyLIEF PROPERTIES SUFFIX ".so")
elseif(WIN32)
  set_target_properties(pyLIEF PROPERTIES SUFFIX ".pyd")
endif()

if (WIN32)
  target_link_libraries(pyLIEF PUBLIC ${PYTHON_LIBRARIES})
endif()

if(SKBUILD)
  if(LIEF_PYTHON_EDITABLE)
    install(TARGETS pyLIEF LIBRARY DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/lief)
  else()
    install(TARGETS pyLIEF LIBRARY DESTINATION ${SKBUILD_PLATLIB_DIR}/lief/)
  endif()
endif()
