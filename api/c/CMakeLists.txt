include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

set(LIEF_C_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/LIEF.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/logging.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/types.h"
)

set(LIEF_C_SRC "${CMAKE_CURRENT_LIST_DIR}/logging.cpp")

if (LIEF_ELF)
  include("${CMAKE_CURRENT_LIST_DIR}/ELF/CMakeLists.txt")
endif()

if (LIEF_PE)
  include("${CMAKE_CURRENT_LIST_DIR}/PE/CMakeLists.txt")
endif()

if (LIEF_MACHO)
  include("${CMAKE_CURRENT_LIST_DIR}/MachO/CMakeLists.txt")
endif()

source_group("Header Files\\C API" FILES ${LIEF_C_INCLUDE_FILES})

target_sources(LIB_LIEF PRIVATE "${LIEF_C_SRC}"  ${LIEF_C_INCLUDE_FILES})

