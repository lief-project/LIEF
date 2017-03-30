set(LIEF_ELF_SRC
  ${CMAKE_CURRENT_LIST_DIR}/DynamicEntryArray.cpp
  ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
  ${CMAKE_CURRENT_LIST_DIR}/SymbolVersionRequirement.cpp
  ${CMAKE_CURRENT_LIST_DIR}/SymbolVersionAuxRequirement.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Binary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp
  ${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DynamicSharedObject.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Segment.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Section.cpp
  ${CMAKE_CURRENT_LIST_DIR}/SymbolVersionAux.cpp
  ${CMAKE_CURRENT_LIST_DIR}/GnuHash.cpp
  ${CMAKE_CURRENT_LIST_DIR}/SymbolVersion.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Builder.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DynamicEntryLibrary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DataHandler
  ${CMAKE_CURRENT_LIST_DIR}/DataHandler/Node.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DataHandler/Handler.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Relocation.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DynamicEntryRunPath.cpp
  ${CMAKE_CURRENT_LIST_DIR}/SymbolVersionDefinition.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DynamicEntry.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DynamicEntryRpath.cpp)


target_sources(LIB_LIEF_STATIC PRIVATE ${LIEF_ELF_SRC})
target_sources(LIB_LIEF_SHARED PRIVATE ${LIEF_ELF_SRC})

file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/enums.inc      LIEF_ELF_ENUMS)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/structures.inc LIEF_ELF_STRUCTURES)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/enums.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/enums.hpp
  @ONLY
)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Structures.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/Structures.hpp
  @ONLY
)
