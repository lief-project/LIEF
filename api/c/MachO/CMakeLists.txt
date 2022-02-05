include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

set(LIEF_API_C_MACHO_SRC
  "${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Parser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Segment.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
)


set(LIEF_API_C_MACHO_INCLUDE_FILES_CPP
  "${CMAKE_CURRENT_LIST_DIR}/Header.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadCommand.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Segment.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.hpp"
)


set(LIEF_API_C_MACHO_INCLUDE_FILES_C
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/enums.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Binary.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/EnumToString.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Header.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/LoadCommand.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Section.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Segment.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Symbol.h"
)


set(LIEF_C_MACHO_INC "${LIEF_API_C_MACHO_INCLUDE_FILES_C}" "${LIEF_API_C_MACHO_INCLUDE_FILES_CPP}")

source_group("Source Files\\C API\\MachO" FILES ${LIEF_API_C_MACHO_SRC})
source_group("Header Files\\C API\\MachO" FILES ${LIEF_C_MACHO_INC})

target_sources(LIB_LIEF PRIVATE "${LIEF_API_C_MACHO_SRC}" ${LIEF_C_MACHO_INC})
