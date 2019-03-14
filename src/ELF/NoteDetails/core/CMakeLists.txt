set(LIEF_ELF_CORE_NOTES_SRC
  "${CMAKE_CURRENT_LIST_DIR}/CorePrPsInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/CorePrPsInfo.tcc"
)

set(LIEF_ELF_CORE_NOTES_INC
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ELF/NoteDetails/core/CorePrPsInfo.hpp"
)

if (LIEF_ELF)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_ELF_CORE_NOTES_SRC}
    ${LIEF_ELF_CORE_NOTES_INC})
endif()

