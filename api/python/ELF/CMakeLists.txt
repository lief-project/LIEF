set(LIEF_PYTHON_ELF_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyELF.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbolVersionAuxRequirement.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbolVersion.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicEntryRunPath.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbolVersionRequirement.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBinary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbolVersionDefinition.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbolVersionAux.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicEntryArray.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicEntryFlags.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySegment.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySection.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicEntryRpath.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRelocation.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicSharedObject.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicEntryLibrary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyGnuHash.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySysvHash.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBuilder.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyEnums.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pySizes.cpp"
)

set(LIEF_PYTHON_ELF_NOTE
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyNote.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyNoteDetails.cpp"
)

list(APPEND LIEF_PYTHON_ELF_SRC ${LIEF_PYTHON_ELF_NOTE})

include("${CMAKE_CURRENT_LIST_DIR}/objects/NoteDetails/CMakeLists.txt")

set(LIEF_PYTHON_ELF_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyELF.hpp")

source_group("Source Files\\ELF" FILES ${LIEF_PYTHON_ELF_SRC})
source_group("Header Files\\ELF" FILES ${LIEF_PYTHON_ELF_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_ELF_SRC}" "${LIEF_PYTHON_ELF_HDR}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}")


