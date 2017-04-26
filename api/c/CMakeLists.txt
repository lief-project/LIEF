include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

set(LIEF_C_ELF_SRC
  "${CMAKE_CURRENT_LIST_DIR}/ELF/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ELF/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ELF/Segment.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ELF/DynamicEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ELF/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ELF/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ELF/EnumToString.cpp")


set(LIEF_C_PE_SRC
  "${CMAKE_CURRENT_LIST_DIR}/PE/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PE/DosHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PE/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PE/OptionalHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PE/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PE/DataDirectory.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/PE/EnumToString.cpp")

set(LIEF_C_MACHO_SRC
  "${CMAKE_CURRENT_LIST_DIR}/MachO/Parser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MachO/LoadCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MachO/Segment.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MachO/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MachO/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MachO/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MachO/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/MachO/EnumToString.cpp")

set(LIEF_C_ELF_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Binary.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/ELF/Binary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/DynamicEntry.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/ELF/DynamicEntry.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/EnumToString.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Header.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/ELF/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Section.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/ELF/Section.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Segment.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/ELF/Segment.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Symbol.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/ELF/Symbol.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/structures.h"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/enums.h")

set(LIEF_C_PE_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/Binary.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/PE/Binary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/DataDirectory.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/PE/DataDirectory.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/DosHeader.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/PE/DosHeader.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/EnumToString.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/Header.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/PE/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/OptionalHeader.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/PE/OptionalHeader.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/Section.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/PE/Section.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/structures.h"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/PE/enums.h")

set(LIEF_C_MACHO_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Binary.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/MachO/Binary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/EnumToString.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Header.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/MachO/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/LoadCommand.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/MachO/LoadCommand.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Section.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/MachO/Section.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Segment.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/MachO/Segment.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO/Symbol.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/MachO/Symbol.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/structures.h"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/MachO/enums.h")

set(LIEF_C_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/MachO.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/LIEF.h")

set(LIEF_C_SRC ${LIEF_C_INCLUDE_FILES})

if (LIEF_ELF)
  set(LIEF_C_SRC "${LIEF_C_SRC}" "${LIEF_C_ELF_SRC}" ${LIEF_C_ELF_INCLUDE_FILES})
  source_group("Source Files\\C API\\ELF" FILES ${LIEF_C_ELF_SRC})
  source_group("Header Files\\C API\\ELF" FILES ${LIEF_C_ELF_INCLUDE_FILES})
endif()

if (LIEF_PE)
  set(LIEF_C_SRC "${LIEF_C_SRC}" "${LIEF_C_PE_SRC}" ${LIEF_C_PE_INCLUDE_FILES})
  source_group("Source Files\\C API\\PE" FILES ${LIEF_C_PE_SRC})
  source_group("Header Files\\C API\\PE" FILES ${LIEF_C_PE_INCLUDE_FILES})
endif()

if (LIEF_MACHO)
  set(LIEF_C_SRC "${LIEF_C_SRC}" "${LIEF_C_MACHO_SRC}" ${LIEF_C_MACHO_INCLUDE_FILES})
  source_group("Source Files\\C API\\MachO" FILES ${LIEF_C_MACHO_SRC})
  source_group("Header Files\\C API\\MachO" FILES ${LIEF_C_MACHO_INCLUDE_FILES})
endif()

source_group("Header Files\\C API" FILES ${LIEF_C_INCLUDE_FILES})

target_sources(LIB_LIEF_STATIC PRIVATE "${LIEF_C_SRC}")
target_sources(LIB_LIEF_SHARED PRIVATE "${LIEF_C_SRC}")

