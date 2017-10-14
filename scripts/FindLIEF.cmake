#.rst:
# FindLIEF
# --------
#
# Find the native LIEF includes and library.
#
# IMPORTED Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines :prop_tgt:`IMPORTED` target ``LIEF::LIEF``, if
# LIEF has been found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module defines the following variables:
#
# ::
#
#   LIEF_INCLUDE_DIRS   - Where to find LIEF/LIEF.hpp, etc.
#   LIEF_LIBRARIES      - List of libraries when using LIEF.
#   LIEF_FOUND          - True if LIEF found.
#
# ::
#
#   LIEF_VERSION_STRING - The version of LIEF found (x.y.z)
#   LIEF_VERSION_MAJOR  - The major version of LIEF
#   LIEF_VERSION_MINOR  - The minor version of LIEF
#   LIEF_VERSION_PATCH  - The patch version of LIEF
#
# Hints
# ^^^^^
#
# A user may set ``LIEF_ROOT`` to a LIEF installation root to tell this
# module where to look.
#
# To choose between STATIC and SHARED version of LIEF library, one
# can use ``COMPONENTS STATIC`` of ``COMPONENTS SHARED``
#
# .. code-block:: cmake
#
#   find_package(LIEF 0.8.0 REQUIRED COMPONENTS STATIC)



set(_LIEF_SEARCHES)
# Search LIEF_ROOT first if it is set.
if(LIEF_ROOT)
  set(_LIEF_SEARCH_ROOT PATHS ${LIEF_ROOT} NO_DEFAULT_PATH)
  list(APPEND _LIEF_SEARCHES _LIEF_SEARCH_ROOT)
endif()

set(LIEF_NAMES LIEF)

if (LIEF_FIND_COMPONENTS AND LIEF_FIND_REQUIRED_STATIC AND LIEF_FIND_REQUIRED_SHARED)
  message(WARNING "Two incompatible components specified : static and shared. We are going to ignore the 'shared' component.")
  list(REMOVE_ITEM LIEF_FIND_COMPONENTS SHARED)
  unset(LIEF_FIND_REQUIRED_SHARED)
endif()

set(LIBRARY_SUFFIXES_SAVED ${CMAKE_FIND_LIBRARY_SUFFIXES})

if (NOT LIEF_FIND_COMPONENTS)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX} ${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

if(LIEF_FIND_COMPONENTS AND LIEF_FIND_REQUIRED_STATIC)
  unset(_LIEF_LIBRARY CACHE)
  unset(LIEF_LIBRARY)
  unset(LIEF_FOUND)
  unset(LIEF_LIBRARIES)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

if(LIEF_FIND_COMPONENTS AND LIEF_FIND_REQUIRED_SHARED)
  unset(_LIEF_LIBRARY CACHE)
  unset(LIEF_LIBRARY)
  unset(LIEF_FOUND)
  unset(LIEF_LIBRARIES)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()

# Try each search configuration.
foreach(search ${_LIEF_SEARCHES})
  find_path(LIEF_INCLUDE_DIR
    NAMES LIEF/LIEF.hpp
    PATH ${${search}}
    PATH_SUFFIXES include)
endforeach()

# Allow LIEF_LIBRARY to be set manually, as the location of the LIEF library
if(NOT LIEF_LIBRARY)
  foreach(search ${_LIEF_SEARCHES})
    find_library(_LIEF_LIBRARY
      NAMES ${LIEF_NAMES}
      PATHS ${${search}}
      PATH_SUFFIXES lib lib64)
  endforeach()

  if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/SelectLibraryConfigurations.cmake")
    include(${CMAKE_CURRENT_LIST_DIR}/SelectLibraryConfigurations.cmake)
  else()
    include(SelectLibraryConfigurations)
  endif()

  select_library_configurations(LIEF)

  set(LIEF_LIBRARY ${_LIEF_LIBRARY})
endif()


unset(LIEF_NAMES)

mark_as_advanced(LIEF_INCLUDE_DIR)

if(LIEF_INCLUDE_DIR AND EXISTS "${LIEF_INCLUDE_DIR}/LIEF/version.h")
  file(STRINGS "${LIEF_INCLUDE_DIR}/LIEF/version.h" LIEF_H REGEX "^#define LIEF_VERSION \"[^\"]*\"$")

  string(REGEX REPLACE "^.*LIEF_VERSION \"([0-9]+).*$" "\\1"                   LIEF_VERSION_MAJOR "${LIEF_H}")
  string(REGEX REPLACE "^.*LIEF_VERSION \"[0-9]+\\.([0-9]+).*$" "\\1"          LIEF_VERSION_MINOR "${LIEF_H}")
  string(REGEX REPLACE "^.*LIEF_VERSION \"[0-9]+\\.[0-9]+\\.([0-9]+).*$" "\\1" LIEF_VERSION_PATCH "${LIEF_H}")
  set(LIEF_VERSION_STRING "${LIEF_VERSION_MAJOR}.${LIEF_VERSION_MINOR}.${LIEF_VERSION_PATCH}")

  set(LIEF_MAJOR_VERSION "${LIEF_VERSION_MAJOR}")
  set(LIEF_MINOR_VERSION "${LIEF_VERSION_MINOR}")
  set(LIEF_PATCH_VERSION "${LIEF_VERSION_PATCH}")
endif()


if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/FindPackageHandleStandardArgs.cmake")
  include(${CMAKE_CURRENT_LIST_DIR}/FindPackageHandleStandardArgs.cmake)
else()
  include(FindPackageHandleStandardArgs)
endif()
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIEF REQUIRED_VARS LIEF_LIBRARY LIEF_INCLUDE_DIR
                                       VERSION_VAR LIEF_VERSION_STRING)


if(LIEF_FOUND)
  set(LIEF_INCLUDE_DIRS ${LIEF_INCLUDE_DIR})

  if(NOT LIEF_LIBRARIES)
    set(LIEF_LIBRARIES ${LIEF_LIBRARY})
  endif()

  if(NOT TARGET LIEF::LIEF)
    add_library(LIEF::LIEF UNKNOWN IMPORTED)
    set_target_properties(LIEF::LIEF PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${LIEF_INCLUDE_DIRS}")

    if(LIEF_LIBRARY)
      set_property(TARGET LIEF::LIEF APPEND PROPERTY
        IMPORTED_CONFIGURATIONS RELEASE)
      set_target_properties(LIEF::LIEF PROPERTIES
        IMPORTED_LOCATION_RELEASE "${LIEF_LIBRARY}")
    endif()

    if(NOT LIEF_LIBRARY)
      set_property(TARGET LIEF::LIEF APPEND PROPERTY
        IMPORTED_LOCATION "${LIEF_LIBRARY}")
    endif()
  endif()
endif()

# Restore
set(CMAKE_FIND_LIBRARY_SUFFIXES ${LIBRARY_SUFFIXES_SAVED})
