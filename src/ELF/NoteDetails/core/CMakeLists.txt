set(LIEF_ELF_CORE_NOTES_SRC
  "${CMAKE_CURRENT_LIST_DIR}/CorePrPsInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/CorePrPsInfo.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/CoreFile.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/CoreFile.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/CorePrStatus.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/CorePrStatus.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/CoreAuxv.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/CoreAuxv.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/CoreSigInfo.cpp"
)

set(LIEF_ELF_CORE_NOTES_INC
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/core/CoreFile.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/core/CoreAuxv.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/core/CoreSigInfo.hpp"
)

if (LIEF_ELF)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_ELF_CORE_NOTES_SRC}
    ${LIEF_ELF_CORE_NOTES_INC})
endif()

