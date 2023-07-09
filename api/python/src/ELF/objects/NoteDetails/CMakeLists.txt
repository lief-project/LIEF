set(LIEF_PYTHON_ELF_NOTE_DETAILS_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pyAndroidNote.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyNoteAbi.cpp"
)

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_ELF_NOTE_DETAILS_SRC}")

add_subdirectory(core)

