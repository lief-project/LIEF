set(LIEF_PYTHON_ELF_NOTE_DETAILS_CORE
  "${CMAKE_CURRENT_LIST_DIR}/pyCorePrPsInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyCoreFile.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyCoreFileEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyCorePrStatus.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyCoreAuxv.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyCoreSigInfo.cpp"
)
target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_ELF_NOTE_DETAILS_CORE}")



