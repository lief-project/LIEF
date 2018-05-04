file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/enums.inc      LIEF_DEX_ENUMS)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/structures.inc LIEF_DEX_STRUCTURES)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/enums.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/DEX/enums.hpp
  @ONLY
)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Structures.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/DEX/Structures.hpp
  @ONLY
)

set(LIEF_DEX_SRC
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.tcc
  ${CMAKE_CURRENT_LIST_DIR}/File.cpp
  ${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.tcc
  ${CMAKE_CURRENT_LIST_DIR}/Class.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Method.cpp
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
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/CodeInfo.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/type_traits.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Type.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/Prototype.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/MapList.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/MapItem.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/instructions.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/hash.hpp"

  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/DEX/Structures.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/DEX/enums.hpp"
)

# JSON Part
# =========
set(LIEF_DEX_JSON_SRC "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
set(LIEF_DEX_JSON_HDR "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/DEX/json.hpp")

if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_DEX_SRC       ${LIEF_DEX_JSON_SRC})
  list(APPEND LIEF_DEX_INC_FILES ${LIEF_DEX_JSON_HDR})
endif()

source_group("Source Files\\DEX" FILES ${LIEF_DEX_SRC})
source_group("Header Files\\DEX" FILES ${LIEF_DEX_INC_FILES})

if (LIEF_DEX)
  target_sources(LIB_LIEF_STATIC PRIVATE
    ${LIEF_DEX_SRC}
    ${LIEF_DEX_INC_FILES}
  )

  target_sources(LIB_LIEF_SHARED PRIVATE
    ${LIEF_DEX_SRC}
    ${LIEF_DEX_INC_FILES}
  )
endif()
