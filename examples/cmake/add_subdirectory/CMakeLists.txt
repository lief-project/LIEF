cmake_minimum_required(VERSION 3.21)

project(SubdirLIEF LANGUAGES CXX)

# Use LIEF as an embedded/vendored project
# ========================================

# LIEF build config. Set the default options for LIEF's project setup
option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded" CACHE STRING "CRT option")
endif()


# If you have LIEF as a submodule in a directory, then you can add it to this
# project with ``add_subdirectory``
# NOTE: This submodule does not exist for this example, but it does the same
# thing as FetchContent without the download part
set(vendorLIEF_submodule_dir "${CMAKE_CURRENT_LIST_DIR}/LIEF")
if(EXISTS "${vendorLIEF_submodule_dir}")
  add_subdirectory("${vendorLIEF_submodule_dir}")

# Else, we'll specify how to obtain LIEF another way (downloading)
else()
  # CMake 3.11 has FetchContent which provides a simple experience for what
  # we're trying to do
  cmake_minimum_required(VERSION 3.11)

  # URL of the LIEF repo (Can be your fork)
  set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

  # LIEF's version to be used (can be 'main')
  set(LIEF_VERSION 0.13.0)

  include(FetchContent)
  FetchContent_Declare(LIEF
    GIT_REPOSITORY  "${LIEF_GIT_URL}"
    GIT_TAG         ${LIEF_VERSION}
    # You may specify an existing LIEF source directory if you don't want to
    # download. Just comment out the above ``GIT_*`` commands and uncoment the
    # following ``SOURCE_DIR`` line
    #SOURCE_DIR      "${CMAKE_CURRENT_LIST_DIR}/../../.."
    )

  if(${CMAKE_VERSION} VERSION_LESS "3.14.0")
    # CMake 3.11 to 3.13 needs more verbose method to make LIEF available
    FetchContent_GetProperties(LIEF)
    if(NOT LIEF_POPULATED)
      FetchContent_Populate(LIEF)
      add_subdirectory(${LIEF_SOURCE_DIR} ${LIEF_BINARY_DIR})
    endif()
  else()
    # CMake 3.14+ has single function to make LIEF available (recommended)
    FetchContent_MakeAvailable(LIEF)
  endif()
endif()


# Add our executable
# ==================
add_executable(HelloLIEF main.cpp)

# Enable C++11
set_property(TARGET HelloLIEF
             PROPERTY CXX_STANDARD           11
             PROPERTY CXX_STANDARD_REQUIRED  ON)

# Link the executable with LIEF
target_link_libraries(HelloLIEF PUBLIC LIEF::LIEF)
