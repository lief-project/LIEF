set(LIEF_ELF_NOTE_DETAILS_SRC
  "${CMAKE_CURRENT_LIST_DIR}/AndroidNote.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/NoteAbi.cpp"
)

set(LIEF_ELF_NOTE_DETAILS_INC
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/AndroidNote.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/NoteAbi.hpp"
)

if (LIEF_ELF)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_ELF_NOTE_DETAILS_SRC}
    ${LIEF_ELF_NOTE_DETAILS_INC})
endif()


include("${CMAKE_CURRENT_LIST_DIR}/core/CMakeLists.txt")
