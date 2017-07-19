cmake_minimum_required(VERSION 3.1)

project(CMakeLIEF)

# Use LIEF with 'find_package()'
# ==============================

# Custom path to the LIEF install directory
set(LIEF_ROOT CACHE PATH ${CMAKE_INSTALL_PREFIX})

# Directory to 'FindLIEF.cmake'
list(APPEND CMAKE_MODULE_PATH ${LIEF_ROOT}/share/LIEF/cmake)

# include 'FindLIEF.cmake'
include(FindLIEF)

# Find LIEF
find_package(LIEF REQUIRED COMPONENTS STATIC) # COMPONENTS: <SHARED | STATIC> - Default: STATIC

# Add our executable
# ==================
add_executable(HelloLIEF main.cpp)

if (MSVC)
  # Used for the 'and', 'or' ... keywords - See: http://www.cplusplus.com/reference/ciso646/
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
target_link_libraries(HelloLIEF PUBLIC ${LIEF_LIBRARIES})
