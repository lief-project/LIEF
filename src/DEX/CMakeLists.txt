set(LIEF_DEX_SRC
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.tcc
  ${CMAKE_CURRENT_LIST_DIR}/File.cpp
  ${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.tcc
  ${CMAKE_CURRENT_LIST_DIR}/Class.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Method.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Field.cpp
  ${CMAKE_CURRENT_LIST_DIR}/instructions.cpp
  ${CMAKE_CURRENT_LIST_DIR}/CodeInfo.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Type.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Prototype.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MapList.cpp
  ${CMAKE_CURRENT_LIST_DIR}/MapItem.cpp
  ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
  ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
)

set(LIEF_DEX_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/File.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Class.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Method.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Field.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/CodeInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/types.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Type.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Prototype.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/MapList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/MapItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/instructions.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/hash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/enums.hpp"

  "${CMAKE_CURRENT_LIST_DIR}/Structures.hpp"
)


# JSON Public API: Always present
list(APPEND LIEF_DEX_SRC       "${CMAKE_CURRENT_LIST_DIR}/json_api.cpp")
list(APPEND LIEF_DEX_INC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/json.hpp")

# JSON Impl
if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_DEX_SRC       "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
  list(APPEND LIEF_DEX_INC_FILES "${CMAKE_CURRENT_LIST_DIR}/json_internal.hpp")
endif()

source_group("Source Files\\DEX" FILES ${LIEF_DEX_SRC})
source_group("Header Files\\DEX" FILES ${LIEF_DEX_INC_FILES})

if (LIEF_DEX)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_DEX_SRC}
    ${LIEF_DEX_INC_FILES}
  )
endif()
