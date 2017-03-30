# Locate LIEF
#
# This module defines
#  LIEF_FOUND, if false, do not try to link to yaml-cpp
#  LIEF_LIBNAME, name of yaml library
#  LIEF_LIBRARY, where to find lief
#  LIEF_LIBRARY_RELEASE, where to find Release or RelWithDebInfo lief
#  LIEF_LIBRARY_DEBUG, where to find Debug version of LIEF
#  LIEF_INCLUDE_DIR, where to find LIEF.hpp
#  LIEF_LIBRARY_DIR, the directories to find LIEF_LIBRARY
#
# By default, the shared libraries of LIEF will be found. To find the static ones instead,
# you must set the LIEF_USE_STATIC_LIBS variable to TRUE before calling find_package(LIEF ...)


if(LIEF_USE_STATIC_LIBS)
  set(LIEF_STATIC libLIEF.a)
endif()

set(LIEF_LIBNAME "libLIEF" CACHE STRING "Name of LIEF library")


# Find include directory
# ======================
find_path(LIEF_INCLUDE_DIR
  NAMES LIEF/LIEF.hpp
  PATH_SUFFIXES include
  PATHS
    /usr/local/include/
    /usr/include/)


# Find the library
# ================
find_library(LIEF_LIBRARY_RELEASE
  NAMES ${LIEF_STATIC} libLIEF LIEF
  PATH_SUFFIXES lib64 lib Release RelWithDebInfo
  PATHS
    /usr/local
    /usr)


set(LIEF_LIBRARY ${LIEF_LIBRARY_RELEASE})
if(CMAKE_BUILD_TYPE MATCHES Debug AND EXISTS ${LIEF_LIBRARY_DEBUG})
  set(LIEF_LIBRARY ${LIEF_LIBRARY_DEBUG})
endif()


get_filename_component(LIEF_LIBRARY_RELEASE_DIR ${LIEF_LIBRARY_RELEASE} PATH)
set(LIEF_LIBRARY_DIR ${LIEF_LIBRARY_RELEASE_DIR})

# handle the QUIETLY and REQUIRED arguments and set LIEF_FOUND to TRUE if all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIEF DEFAULT_MSG
  LIEF_INCLUDE_DIR
  LIEF_LIBRARY
  LIEF_LIBRARY_DIR)

mark_as_advanced(
  LIEF_INCLUDE_DIR
  LIEF_LIBRARY_DIR
  LIEF_LIBRARY
  LIEF_LIBRARY_RELEASE
  LIEF_LIBRARY_RELEASE_DIR)
