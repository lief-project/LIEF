include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

set(LIEF_C_ELF_SRC
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Segment.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntry.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/utils.cpp"
)


set(LIEF_API_C_ELF_INCLUDE_FILES_CPP
  "${CMAKE_CURRENT_LIST_DIR}/Binary.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/DynamicEntry.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Segment.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.hpp"
)

set(LIEF_API_C_ELF_INCLUDE_FILES_C
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Binary.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/DynamicEntry.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/EnumToString.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Header.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Section.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Segment.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/Symbol.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/enums.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/ELF/utils.h"
)

set(LIEF_C_ELF_INC "${LIEF_API_C_ELF_INCLUDE_FILES_C}" "${LIEF_API_C_ELF_INCLUDE_FILES_CPP}")

source_group("Source Files\\C API\\ELF" FILES ${LIEF_API_C_ELF_SRC})
source_group("Header Files\\C API\\ELF" FILES ${LIEF_C_ELF_INC})

target_sources(LIB_LIEF PRIVATE "${LIEF_C_ELF_SRC}" "${LIEF_C_ELF_INC}")
