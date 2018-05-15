
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/enums.inc"      LIEF_ELF_ENUMS)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/structures.inc" LIEF_ELF_STRUCTURES)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/enums.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/enums.hpp"
  @ONLY
)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Structures.hpp.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/Structures.hpp"
  @ONLY
)

set(LIEF_ELF_SRC
  "${CMAKE_CURRENT_LIST_DIR}/Convert.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntryArray.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/utils.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SymbolVersionRequirement.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SymbolVersionAuxRequirement.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicSharedObject.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Segment.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SymbolVersionAux.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/GnuHash.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SysvHash.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SymbolVersion.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Builder.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntryLibrary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DataHandler/Node.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DataHandler/Handler.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Parser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Relocation.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntryRunPath.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/SymbolVersionDefinition.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntryRpath.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntryFlags.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Builder.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/Parser.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/hash.cpp"
)

set(LIEF_ELF_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Binary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Builder.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DynamicEntry.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DynamicEntryArray.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DynamicEntryFlags.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DynamicEntryLibrary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DynamicEntryRpath.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DynamicEntryRunPath.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DynamicSharedObject.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/GnuHash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/SysvHash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Relocation.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Section.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Segment.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Symbol.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/SymbolVersion.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/SymbolVersionAux.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/SymbolVersionAuxRequirement.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/SymbolVersionDefinition.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/SymbolVersionRequirement.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/type_traits.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/hash.hpp"

  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/Structures.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/ELF/enums.hpp"

  "${CMAKE_CURRENT_LIST_DIR}/RelocationSizes.hpp"
  )

set(LIEF_ELF_DATA_HANDLER_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DataHandler/Handler.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/DataHandler/Node.hpp")

# JSON Part
# =========
set(LIEF_ELF_JSON_SRC "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
set(LIEF_ELF_JSON_HDR "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/json.hpp")

# Notes part
# ==========
set(LIEF_ELF_NOTE_SRC
  "${CMAKE_CURRENT_LIST_DIR}/Note.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/AndroidNote.cpp"
)

set(LIEF_ELF_NOTE_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Note.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/AndroidNote.hpp"
)

list(APPEND LIEF_ELF_SRC ${LIEF_ELF_NOTE_SRC})
list(APPEND LIEF_ELF_INC_FILES ${LIEF_ELF_NOTE_INCLUDE_FILES})


if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_ELF_SRC       ${LIEF_ELF_JSON_SRC})
  list(APPEND LIEF_ELF_INC_FILES ${LIEF_ELF_JSON_HDR})
endif()

set(LIEF_ELF_INCLUDE_FILES
  ${LIEF_ELF_INC_FILES}
#  ${LIEF_ELF_RELOC_INCLUDE_FILES}
  ${LIEF_ELF_DATA_HANDLER_INCLUDE_FILES})

source_group("Source Files\\ELF" FILES ${LIEF_ELF_SRC})
source_group("Header Files\\ELF" FILES ${LIEF_ELF_INC_FILES})
source_group("Header Files\\ELF\\DataHandler" FILES ${LIEF_ELF_DATA_HANDLER_INCLUDE_FILES})
#source_group("Header Files\\ELF\\Relocations" FILES ${LIEF_ELF_RELOC_INCLUDE_FILES})

if (LIEF_ELF)
  target_sources(LIB_LIEF_STATIC PRIVATE
    ${LIEF_ELF_SRC}
    ${LIEF_ELF_INCLUDE_FILES})

  target_sources(LIB_LIEF_SHARED PRIVATE
    ${LIEF_ELF_SRC}
    ${LIEF_ELF_INCLUDE_FILES})
endif()
