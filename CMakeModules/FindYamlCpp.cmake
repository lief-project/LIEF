# Locate yaml-cpp
#
# This module defines
#  YAMLCPP_FOUND, if false, do not try to link to yaml-cpp
#  YAMLCPP_LIBNAME, name of yaml library
#  YAMLCPP_LIBRARY, where to find yaml-cpp
#  YAMLCPP_LIBRARY_RELEASE, where to find Release or RelWithDebInfo yaml-cpp
#  YAMLCPP_LIBRARY_DEBUG, where to find Debug yaml-cpp
#  YAMLCPP_INCLUDE_DIR, where to find yaml.h
#  YAMLCPP_LIBRARY_DIR, the directories to find YAMLCPP_LIBRARY
#
# By default, the dynamic libraries of yaml-cpp will be found. To find the static ones instead,
# you must set the YAMLCPP_USE_STATIC_LIBS variable to TRUE before calling find_package(YamlCpp ...)

# attempt to find static library first if this is set
if(YAMLCPP_USE_STATIC_LIBS)
    set(YAMLCPP_STATIC libyaml-cpp.a)
    set(YAMLCPP_STATIC_DEBUG libyaml-cpp-dbg.a)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")    ### Set Yaml libary name for Windows
  set(YAMLCPP_LIBNAME "libyaml-cppmd" CACHE STRING "Name of YAML library")
  set(YAMLCPP_LIBNAME optimized ${YAMLCPP_LIBNAME} debug ${YAMLCPP_LIBNAME}d)
else()                      ### Set Yaml libary name for Unix, Linux, OS X, etc
  set(YAMLCPP_LIBNAME "yaml-cpp" CACHE STRING "Name of YAML library")
endif()

# find the yaml-cpp include directory
find_path(YAMLCPP_INCLUDE_DIR
  NAMES yaml-cpp/yaml.h
  PATH_SUFFIXES include
  PATHS
    ${PROJECT_SOURCE_DIR}/dependencies/yaml-cpp-0.5.1/include
    ~/Library/Frameworks/yaml-cpp/include/
    /Library/Frameworks/yaml-cpp/include/
    /usr/local/include/
    /usr/include/
    /sw/yaml-cpp/         # Fink
    /opt/local/yaml-cpp/  # DarwinPorts
    /opt/csw/yaml-cpp/    # Blastwave
    /opt/yaml-cpp/)

# find the release yaml-cpp library
find_library(YAMLCPP_LIBRARY_RELEASE
  NAMES ${YAMLCPP_STATIC} yaml-cpp libyaml-cppmd.lib
  PATH_SUFFIXES lib64 lib Release RelWithDebInfo
  PATHS
    ${PROJECT_SOURCE_DIR}/dependencies/yaml-cpp-0.5.1/
    ${PROJECT_SOURCE_DIR}/dependencies/yaml-cpp-0.5.1/build
    ~/Library/Frameworks
    /Library/Frameworks
    /usr/local
    /usr
    /sw
    /opt/local
    /opt/csw
    /opt)

# find the debug yaml-cpp library
find_library(YAMLCPP_LIBRARY_DEBUG
  NAMES ${YAMLCPP_STATIC_DEBUG} yaml-cpp-dbg libyaml-cppmdd.lib
  PATH_SUFFIXES lib64 lib Debug
  PATHS
    ${PROJECT_SOURCE_DIR}/dependencies/yaml-cpp-0.5.1/
    ${PROJECT_SOURCE_DIR}/dependencies/yaml-cpp-0.5.1/build
    ~/Library/Frameworks
    /Library/Frameworks
    /usr/local
    /usr
    /sw
    /opt/local
    /opt/csw
    /opt)

# set library vars
set(YAMLCPP_LIBRARY ${YAMLCPP_LIBRARY_RELEASE})
if(CMAKE_BUILD_TYPE MATCHES Debug AND EXISTS ${YAMLCPP_LIBRARY_DEBUG})
  set(YAMLCPP_LIBRARY ${YAMLCPP_LIBRARY_DEBUG})
endif()

get_filename_component(YAMLCPP_LIBRARY_RELEASE_DIR ${YAMLCPP_LIBRARY_RELEASE} PATH)
get_filename_component(YAMLCPP_LIBRARY_DEBUG_DIR ${YAMLCPP_LIBRARY_DEBUG} PATH)
set(YAMLCPP_LIBRARY_DIR ${YAMLCPP_LIBRARY_RELEASE_DIR} ${YAMLCPP_LIBRARY_DEBUG_DIR})

# handle the QUIETLY and REQUIRED arguments and set YAMLCPP_FOUND to TRUE if all listed variables are TRUE
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(YamlCpp DEFAULT_MSG
  YAMLCPP_INCLUDE_DIR
  YAMLCPP_LIBRARY
  YAMLCPP_LIBRARY_DIR)
mark_as_advanced(
  YAMLCPP_INCLUDE_DIR
  YAMLCPP_LIBRARY_DIR
  YAMLCPP_LIBRARY
  YAMLCPP_LIBRARY_RELEASE
  YAMLCPP_LIBRARY_RELEASE_DIR
  YAMLCPP_LIBRARY_DEBUG
  YAMLCPP_LIBRARY_DEBUG_DIR)
