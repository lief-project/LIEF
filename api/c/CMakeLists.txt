include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(LIEF_C_ELF_SRC
  ${CMAKE_CURRENT_LIST_DIR}/ELF/Symbol.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ELF/Section.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ELF/Segment.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ELF/DynamicEntry.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ELF/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ELF/Binary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ELF/EnumToString.cpp)


set(LIEF_C_PE_SRC
  ${CMAKE_CURRENT_LIST_DIR}/PE/Binary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/PE/DosHeader.cpp
  ${CMAKE_CURRENT_LIST_DIR}/PE/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/PE/OptionalHeader.cpp
  ${CMAKE_CURRENT_LIST_DIR}/PE/Section.cpp
  ${CMAKE_CURRENT_LIST_DIR}/PE/DataDirectory.cpp
  ${CMAKE_CURRENT_LIST_DIR}/PE/EnumToString.cpp)


set(LIEF_C_MACHO_SRC
  ${CMAKE_CURRENT_LIST_DIR}/MachO/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MachO/LoadCommand.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MachO/Segment.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MachO/Symbol.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MachO/Section.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MachO/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MachO/Binary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MachO/EnumToString.cpp)

set(LIEF_C_SRC)

if (LIEF_ELF)
  set(LIEF_C_SRC ${LIEF_C_SRC} ${LIEF_C_ELF_SRC})
endif()

if (LIEF_PE)
  set(LIEF_C_SRC ${LIEF_C_SRC} ${LIEF_C_PE_SRC})
endif()

if (LIEF_MACHO)
  set(LIEF_C_SRC ${LIEF_C_SRC} ${LIEF_C_MACHO_SRC})
endif()

target_sources(LIB_LIEF_STATIC PRIVATE ${LIEF_C_SRC})
target_sources(LIB_LIEF_SHARED PRIVATE ${LIEF_C_SRC})

