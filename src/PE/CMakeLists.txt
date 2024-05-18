target_sources(LIB_LIEF PRIVATE
  Binary.cpp
  Builder.cpp
  Builder.tcc
  CodeIntegrity.cpp
  Convert.cpp
  DataDirectory.cpp
  DelayImport.cpp
  DelayImportEntry.cpp
  DosHeader.cpp
  EnumToString.cpp
  Export.cpp
  ExportEntry.cpp
  Header.cpp
  Import.cpp
  ImportEntry.cpp
  OptionalHeader.cpp
  Parser.cpp
  Parser.tcc
  Relocation.cpp
  RelocationEntry.cpp
  ResourceData.cpp
  ResourceDirectory.cpp
  ResourceNode.cpp
  ResourcesManager.cpp
  ResourcesParser.cpp
  RichEntry.cpp
  RichHeader.cpp
  Section.cpp
  Symbol.cpp
  TLS.cpp
  checksum.cpp
  hash.cpp
  json_api.cpp
  utils.cpp
)

add_subdirectory(signature)
add_subdirectory(LoadConfigurations)
add_subdirectory(resources)
add_subdirectory(debug)

if(LIEF_ENABLE_JSON)
  target_sources(LIB_LIEF PRIVATE json.cpp)
endif()
