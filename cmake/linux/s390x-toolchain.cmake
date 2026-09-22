# CMake toolchain file for s390x cross-compilation
# This file configures CMake to cross-compile LIEF for s390x architecture from x86_64 host

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR s390x)

# Specify the cross-compiler
set(CMAKE_C_COMPILER s390x-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER s390x-linux-gnu-g++)
set(CMAKE_AR s390x-linux-gnu-ar)
set(CMAKE_RANLIB s390x-linux-gnu-ranlib)
set(CMAKE_STRIP s390x-linux-gnu-strip)

# Where to look for the target environment
set(CMAKE_FIND_ROOT_PATH /usr/s390x-linux-gnu)

# Search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# Search for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Target IBM z13 or newer for optimal compatibility
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=z13" CACHE STRING "C flags for s390x")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=z13" CACHE STRING "CXX flags for s390x")
