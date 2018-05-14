set(LIEF_PYTHON_MACHO_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyMachO.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDylibCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBinary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyFatBinary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyLoadCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySegmentCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySection.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbolCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyUUID.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySourceVersion.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyVersionMin.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyMainCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDylinker.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDyldInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyFunctionStarts.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRelocation.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRelocationObject.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRelocationDyld.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBindingInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyExportInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyThreadCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRPathCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParserConfig.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDynamicSymbolCommand.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyCodeSignature.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySegmentSplitInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDataInCode.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDataCodeEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySubFramework.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDyldEnvironment.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyMachOStructures.cpp"
)

set(LIEF_PYTHON_MACHO_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyMachO.hpp")

source_group("Source Files\\MachO" FILES ${LIEF_PYTHON_MACHO_SRC})
source_group("Header Files\\MachO" FILES ${LIEF_PYTHON_MACHO_HDR})

target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_MACHO_SRC}" "${LIEF_PYTHON_MACHO_HDR}")



