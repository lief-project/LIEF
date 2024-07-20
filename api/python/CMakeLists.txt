find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)

if (LIEF_PY_LIEF_EXT)
  find_package(LIEF REQUIRED COMPONENTS STATIC)
  message(STATUS "Using pre-installed version of LIEF")
  set(LIEF_TARGET LIEF::LIEF)
  set_target_properties(LIB_LIEF PROPERTIES EXCLUDE_FROM_ALL ON)
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
  set(NANOBIND_VERSION 1.8.0.r43.g45c2a74)
  set(NANOBIND_SHA256 SHA256=a94f4a801cbe6befb2536f6140d8b280f975a63bd21247ad4894f5eff50209e4)
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

set(NANOBIND_OPT
  NB_STATIC
  NOMINSIZE
)

if (LIEF_PYTHON_STATIC)
  list(APPEND NANOBIND_OPT NB_EXT_STATIC)
endif()

nanobind_add_module(
  pyLIEF
  ${NANOBIND_OPT}

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


if (UNIX OR MUSL)
  if (LIEF_PYTHON_STATIC)
    set_target_properties(pyLIEF PROPERTIES SUFFIX ".a")
  else()
    # Even on osx (c.f. EXT_SUFFIX from sysconfig)
    set_target_properties(pyLIEF PROPERTIES SUFFIX ".so")
  endif()
elseif(WIN32)
  if (LIEF_PYTHON_STATIC)
    set_target_properties(pyLIEF PROPERTIES SUFFIX ".lib")
  else()
    set_target_properties(pyLIEF PROPERTIES SUFFIX ".pyd")
  endif()
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

if (LIEF_PYTHON_STATIC)
  install(TARGETS nanobind-static pyLIEF
          DESTINATION lib/python-${Python_VERSION})

  install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lief
    DESTINATION lib/python/typing
    FILES_MATCHING
    REGEX "(.*).(pyi)$")

  install(DIRECTORY ${NB_DIR}/include/
          DESTINATION include/)
endif()
