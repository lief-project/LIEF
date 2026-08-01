include_guard(GLOBAL)

set(LIEF_SUPPORT_CXX11 0)
set(LIEF_SUPPORT_CXX14 0)
set(LIEF_SUPPORT_CXX17 0)

if(cxx_std_11 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  set(LIEF_SUPPORT_CXX11 1)
endif()

if(cxx_std_14 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  set(LIEF_SUPPORT_CXX14 1)
endif()

if(cxx_std_17 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  set(LIEF_SUPPORT_CXX17 1)
endif()

if(NOT LIEF_SUPPORT_CXX17)
  message(FATAL_ERROR
    "LIEF requires a compiler with C++17 support, but 'cxx_std_17' is not "
    "advertised in CMAKE_CXX_COMPILE_FEATURES for "
    "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}.")
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/src/compiler_support.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/compiler_support.h"
  @ONLY
)
