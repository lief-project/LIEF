if(__add_lief_compiler_detection)
	return()
endif()
set(__add_lief_compiler_detection ON)

set(LIEF_SUPPORT_CXX11 0)
set(LIEF_SUPPORT_CXX14 0)
set(LIEF_SUPPORT_CXX17 0)

if (cxx_std_11 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  set(LIEF_SUPPORT_CXX11 1)
endif()

if (cxx_std_14 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  if (${MSVC} AND ${MSVC_TOOLSET_VERSION} GREATER_EQUAL 141)
    set(LIEF_SUPPORT_CXX14 1)
  elseif((NOT DEFINED MSVC) OR (NOT ${MSVC}))
    set(LIEF_SUPPORT_CXX14 1)
  endif()
endif()

if (cxx_std_17 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  if (${MSVC} AND ${MSVC_TOOLSET_VERSION} GREATER_EQUAL 142)
    set(LIEF_SUPPORT_CXX17 1)
  elseif((NOT DEFINED MSVC) OR (NOT ${MSVC}))
    set(LIEF_SUPPORT_CXX17 1)
  endif()
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/src/compiler_support.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/compiler_support.h"
  @ONLY
)

