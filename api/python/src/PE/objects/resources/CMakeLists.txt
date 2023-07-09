set(LIEF_PYTHON_PE_RSRC_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceNode.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceData.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceDirectory.cpp"

  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceIcon.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceVersion.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceVarFileInfo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceFixedFileInfo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceStringFileInfo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLangCodeItem.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceDialog.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceDialogItem.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceStringTable.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyResourceAccelerator.cpp"
)

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_PE_RSRC_SRC}")
