set(LIEF_PYTHON_ELF_OBJECT_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pyParser.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyBinary.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyBuilder.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDynamicEntry.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDynamicEntryArray.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDynamicEntryFlags.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDynamicEntryLibrary.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDynamicEntryRpath.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDynamicEntryRunPath.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDynamicSharedObject.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyGnuHash.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyHeader.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyParserConfig.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyNote.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyNoteDetails.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyRelocation.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySection.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySegment.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySymbol.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySymbolVersion.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySymbolVersionAux.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySymbolVersionAuxRequirement.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySymbolVersionRequirement.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySymbolVersionDefinition.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySysvHash.cpp"
)

target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_ELF_OBJECT_SRC})

add_subdirectory(NoteDetails)

