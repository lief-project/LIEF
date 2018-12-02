cmake_minimum_required(VERSION 3.02)

include(ExternalProject)

project(CMakeLIEF)

# LIEF as an External Project
# ===========================
set(LIEF_PREFIX       "${CMAKE_CURRENT_BINARY_DIR}/LIEF")
set(LIEF_INSTALL_DIR  "${LIEF_PREFIX}")
set(LIEF_INCLUDE_DIRS "${LIEF_PREFIX}/include")

# LIEF static library
set(LIB_LIEF
  "${LIEF_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}LIEF${CMAKE_STATIC_LIBRARY_SUFFIX}")

# URL of the LIEF repo (Can be your fork)
set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

# LIEF's version to be used (can be 'master')
set(LIEF_VERSION 0.9.0)

# LIEF compilation config
set(LIEF_CMAKE_ARGS
  -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
  -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
  -DLIEF_DOC=off
  -DLIEF_PYTHON_API=off
  -DLIEF_EXAMPLES=off
  -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
  -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
)

if (MSVC)
  list(APPEND ${LIEF_CMAKE_ARGS} -DLIEF_USE_CRT_RELEASE=MT)
endif()

ExternalProject_Add(LIEF
  PREFIX           "${PACKER_LIEF_PREFIX}"
  GIT_REPOSITORY   ${LIEF_GIT_URL}
  GIT_TAG          ${LIEF_VERSION}
  INSTALL_DIR      ${LIEF_INSTALL_DIR}
  CMAKE_ARGS       ${LIEF_CMAKE_ARGS}
  BUILD_BYPRODUCTS ${LIEF_LIBRARIES}
  UPDATE_COMMAND   ""
)


# Add our executable
# ==================
add_executable(HelloLIEF main.cpp)

if (MSVC)
  # Used for the 'and', 'or' ... keywords - See: http://www.cplusplus.com/reference/ciso646/
  target_compile_options(HelloLIEF PUBLIC /FIiso646.h)
  set_property(TARGET HelloLIEF PROPERTY LINK_FLAGS /NODEFAULTLIB:MSVCRT)
endif()

# Setup the LIEF include directory
target_include_directories(HelloLIEF
  PUBLIC
  ${LIEF_INCLUDE_DIRS}
)

# Enable C++11
set_property(TARGET HelloLIEF PROPERTY CXX_STANDARD           11)
set_property(TARGET HelloLIEF PROPERTY CXX_STANDARD_REQUIRED  ON)

# Link the executable with LIEF
target_link_libraries(HelloLIEF PUBLIC ${LIB_LIEF})

add_dependencies(HelloLIEF LIEF)
