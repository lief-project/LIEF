set(LIEF_PYTHON_PE_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyUtils.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/objects/pyResourceNode.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyResourceData.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyResourceDirectory.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceIcon.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceVersion.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceVarFileInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceFixedFileInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceStringFileInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyLangCodeItem.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceDialog.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceDialogItem.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceStringTable.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/resources/pyResourceAccelerator.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/objects/pyCodeIntegrity.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDataDirectory.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDosHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRichHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRichEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBuilder.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyOptionalHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRelocationEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBinary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyResourcesManager.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDebug.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyCodeView.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyCodeViewPDB.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyPogo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyPogoEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySection.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyExport.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyImport.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyExportEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRelocation.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyImportEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDelayImport.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDelayImportEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyTLS.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyEnums.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyPE.cpp"
)

set(LIEF_PYTHON_PE_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyPE.hpp")

source_group("Source Files\\PE" FILES ${LIEF_PYTHON_PE_SRC})
source_group("Header Files\\PE" FILES ${LIEF_PYTHON_PE_HDR})

target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_PE_SRC}" "${LIEF_PYTHON_PE_HDR}")


include("${CMAKE_CURRENT_LIST_DIR}/objects/LoadConfigurations/CMakeLists.txt")
include("${CMAKE_CURRENT_LIST_DIR}/objects/signature/CMakeLists.txt")


