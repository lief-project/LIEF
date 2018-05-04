file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/enums.inc      LIEF_VDEX_ENUMS)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/structures.inc LIEF_VDEX_STRUCTURES)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/enums.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/VDEX/enums.hpp
  @ONLY
)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/Structures.hpp.in
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/VDEX/Structures.hpp
  @ONLY
)

set(LIEF_VDEX_SRC
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.tcc
  ${CMAKE_CURRENT_LIST_DIR}/File.cpp
  ${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.tcc
  ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
  ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
)

set(LIEF_VDEX_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/File.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/type_traits.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/hash.hpp"

  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/VDEX/Structures.hpp"
  "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/VDEX/enums.hpp"
)

# JSON Part
# =========
set(LIEF_VDEX_JSON_SRC "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
set(LIEF_VDEX_JSON_HDR "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/json.hpp")

if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_VDEX_SRC       ${LIEF_VDEX_JSON_SRC})
  list(APPEND LIEF_VDEX_INC_FILES ${LIEF_VDEX_JSON_HDR})
endif()

source_group("Source Files\\VDEX" FILES ${LIEF_VDEX_SRC})
source_group("Header Files\\VDEX" FILES ${LIEF_VDEX_INC_FILES})

if (LIEF_VDEX)
  target_sources(LIB_LIEF_STATIC PRIVATE
    ${LIEF_VDEX_SRC}
    ${LIEF_VDEX_INC_FILES}
  )

  target_sources(LIB_LIEF_SHARED PRIVATE
    ${LIEF_VDEX_SRC}
    ${LIEF_VDEX_INC_FILES}
  )
endif()
