include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
set(LIEF_API_C_PE_SRC
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DosHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/OptionalHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/DataDirectory.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Import.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/ImportEntry.cpp"
)


set(LIEF_API_C_PE_INCLUDE_FILES_CPP
  "${CMAKE_CURRENT_LIST_DIR}/Binary.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/DataDirectory.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/DosHeader.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/OptionalHeader.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Import.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/ImportEntry.hpp"
)

set(LIEF_API_C_PE_INCLUDE_FILES_C
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/enums.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/Binary.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/DataDirectory.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/DosHeader.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/EnumToString.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/Header.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/OptionalHeader.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/Section.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/Import.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/api/c/include/LIEF/PE/ImportEntry.h"
)


set(LIEF_C_PE_INC "${LIEF_API_C_PE_INCLUDE_FILES_C}" "${LIEF_API_C_PE_INCLUDE_FILES_CPP}")

source_group("Source Files\\C API\\PE" FILES ${LIEF_API_C_PE_SRC})
source_group("Header Files\\C API\\PE" FILES ${LIEF_C_PE_INC})

target_sources(LIB_LIEF PRIVATE "${LIEF_API_C_PE_SRC}" "${LIEF_C_PE_INC}")
