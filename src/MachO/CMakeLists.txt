target_sources(LIB_LIEF PRIVATE
  AtomInfo.cpp
  Binary.cpp
  Binary.tcc
  BinaryParser.cpp
  BinaryParser.tcc
  BindingInfo.cpp
  BindingInfoIterator.cpp
  BuildToolVersion.cpp
  BuildVersion.cpp
  Builder.cpp
  Builder.tcc
  ChainedBindingInfo.cpp
  ChainedBindingInfoList.cpp
  ChainedFixup.cpp
  ChainedPointerAnalysis.cpp
  CodeSignature.cpp
  CodeSignatureDir.cpp
  DataCodeEntry.cpp
  DataInCode.cpp
  DyldBindingInfo.cpp
  DyldChainedFixups.cpp
  DyldChainedFixupsCreator.cpp
  DyldChainedFormat.cpp
  DyldEnvironment.cpp
  DyldExportsTrie.cpp
  DyldInfo.cpp
  DylibCommand.cpp
  DylinkerCommand.cpp
  DynamicSymbolCommand.cpp
  EncryptionInfo.cpp
  EnumToString.cpp
  ExportInfo.cpp
  FatBinary.cpp
  FilesetCommand.cpp
  FunctionStarts.cpp
  FunctionVariants.cpp
  FunctionVariantFixups.cpp
  Header.cpp
  IndirectBindingInfo.cpp
  LinkEdit.cpp
  LinkerOptHint.cpp
  LoadCommand.cpp
  MainCommand.cpp
  NoteCommand.cpp
  Parser.cpp
  ParserConfig.cpp
  RPathCommand.cpp
  Relocation.cpp
  RelocationDyld.cpp
  RelocationFixup.cpp
  RelocationObject.cpp
  Routine.cpp
  Section.cpp
  SegmentCommand.cpp
  SegmentSplitInfo.cpp
  SourceVersion.cpp
  Stub.cpp
  SubClient.cpp
  SubFramework.cpp
  Symbol.cpp
  SymbolCommand.cpp
  ThreadCommand.cpp
  TrieNode.cpp
  TwoLevelHints.cpp
  UUIDCommand.cpp
  UnknownCommand.cpp
  VersionMin.cpp
  endianness_support.cpp
  exports_trie.cpp
  hash.cpp
  json_api.cpp
  layout_check.cpp
  utils.cpp
)

if(LIEF_ENABLE_JSON)
  target_sources(LIB_LIEF PRIVATE json.cpp)
endif()

