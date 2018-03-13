if(__add_lief_api)
	return()
endif()
set(__add_lief_api ON)

# Python
# ------
if (LIEF_PYTHON_API)
  if(WIN32)
    set(PYTHON_BUILD_LIEF_DIRECTORY "${CMAKE_BINARY_DIR}/api/python/Release")
  else()
    set(PYTHON_BUILD_LIEF_DIRECTORY "${CMAKE_BINARY_DIR}/api/python")
  endif()
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/api/python")
endif()

# C API
# -----
if(LIEF_C_API)

  # ELF
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/enums.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/enums.h"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/structures.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/structures.h"
    @ONLY
  )

  # PE
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/enums.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/enums.h"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/structures.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/structures.h"
    @ONLY
  )

  # MachO
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/enums.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/enums.h"
    @ONLY
  )

  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/structures.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/structures.h"
    @ONLY
  )

  target_include_directories(LIB_LIEF_STATIC
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include")

  target_include_directories(LIB_LIEF_SHARED
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include"
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include")

  include("${CMAKE_CURRENT_SOURCE_DIR}/api/c/CMakeLists.txt")
endif()

