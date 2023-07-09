set(LIEF_PYTHON_PE_OBJECT_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pyParser.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyParserConfig.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyBinary.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyCodeIntegrity.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDataDirectory.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDosHeader.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyRichHeader.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyRichEntry.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyBuilder.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyOptionalHeader.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyRelocationEntry.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourcesManager.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyHeader.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDebug.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyCodeView.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyCodeViewPDB.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyPogo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyPogoEntry.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySection.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyExport.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyImport.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyExportEntry.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyRelocation.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyImportEntry.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDelayImport.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDelayImportEntry.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySymbol.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyTLS.cpp"
)

target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_PE_OBJECT_SRC})

add_subdirectory(resources)
add_subdirectory(signature)
add_subdirectory(LoadConfigurations)

