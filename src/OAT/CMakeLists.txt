set(LIEF_OAT_SRC
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.tcc
  ${CMAKE_CURRENT_LIST_DIR}/Binary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/DexFile.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Class.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Method.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.tcc
  ${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp
  ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
  ${CMAKE_CURRENT_LIST_DIR}/hash.cpp

  ${CMAKE_CURRENT_LIST_DIR}/oat_64.tcc
  ${CMAKE_CURRENT_LIST_DIR}/oat_79.tcc
  ${CMAKE_CURRENT_LIST_DIR}/oat_131.tcc
  ${CMAKE_CURRENT_LIST_DIR}/oat_124.tcc
)

set(LIEF_OAT_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/Binary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/DexFile.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/Class.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/Method.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/type_traits.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/hash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/enums.hpp"

  "${CMAKE_CURRENT_LIST_DIR}/Structures.hpp"
)

# JSON Public API: Always present
list(APPEND LIEF_OAT_SRC       "${CMAKE_CURRENT_LIST_DIR}/json_api.cpp")
list(APPEND LIEF_OAT_INC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/OAT/json.hpp")

# JSON Impl
if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_OAT_SRC       "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
  list(APPEND LIEF_OAT_INC_FILES "${CMAKE_CURRENT_LIST_DIR}/json_internal.hpp")
endif()

source_group("Source Files\\OAT" FILES ${LIEF_OAT_SRC})
source_group("Header Files\\OAT" FILES ${LIEF_OAT_INC_FILES})

if (LIEF_OAT)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_OAT_SRC}
    ${LIEF_OAT_INC_FILES}
  )
endif()
