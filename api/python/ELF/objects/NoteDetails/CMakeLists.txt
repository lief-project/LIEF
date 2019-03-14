set(LIEF_PYTHON_ELF_NOTE_DETAILS_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyAndroidNote.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyNoteAbi.cpp"
)

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_ELF_NOTE_DETAILS_SRC}")

include("${CMAKE_CURRENT_LIST_DIR}/core/CMakeLists.txt")



