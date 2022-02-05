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
  "${CMAKE_CURRENT_LIST_DIR}/Note.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/NoteDetails.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Layout.cpp"
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
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/hash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/Note.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/enums.hpp"
  )

set(LIEF_ELF_DATA_HANDLER_INCLUDE_FILES
  "${CMAKE_CURRENT_LIST_DIR}/DataHandler/Handler.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/DataHandler/Node.hpp")

# Note Details Part
# =================
include("${CMAKE_CURRENT_LIST_DIR}/NoteDetails/CMakeLists.txt")

# JSON Public API: Always present
list(APPEND LIEF_ELF_SRC       "${CMAKE_CURRENT_LIST_DIR}/json_api.cpp")
list(APPEND LIEF_ELF_INC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/json.hpp")

# JSON Impl
if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_ELF_SRC       "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
  list(APPEND LIEF_ELF_INC_FILES "${CMAKE_CURRENT_LIST_DIR}/json_internal.hpp")
endif()

set(LIEF_ELF_INCLUDE_FILES
  ${LIEF_ELF_INC_FILES}
  ${LIEF_ELF_DATA_HANDLER_INCLUDE_FILES})

source_group("Source Files\\ELF" FILES ${LIEF_ELF_SRC})
source_group("Header Files\\ELF" FILES ${LIEF_ELF_INC_FILES})
source_group("Header Files\\ELF\\DataHandler" FILES ${LIEF_ELF_DATA_HANDLER_INCLUDE_FILES})

if (LIEF_ELF)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_ELF_SRC}
    ${LIEF_ELF_INCLUDE_FILES})
endif()
