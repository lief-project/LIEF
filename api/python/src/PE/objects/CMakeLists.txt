target_sources(pyLIEF PRIVATE
  pyParser.cpp
  pyParserConfig.cpp
  pyBinary.cpp
  pyCodeIntegrity.cpp
  pyDataDirectory.cpp
  pyDosHeader.cpp
  pyRichHeader.cpp
  pyRichEntry.cpp
  pyBuilder.cpp
  pyOptionalHeader.cpp
  pyRelocationEntry.cpp
  pyResourcesManager.cpp
  pyHeader.cpp
  pySection.cpp
  pyExport.cpp
  pyImport.cpp
  pyExportEntry.cpp
  pyRelocation.cpp
  pyImportEntry.cpp
  pyDelayImport.cpp
  pyDelayImportEntry.cpp
  pySymbol.cpp
  pyTLS.cpp
  pyLang.cpp
)

add_subdirectory(resources)
add_subdirectory(signature)
add_subdirectory(LoadConfigurations)
add_subdirectory(debug)
