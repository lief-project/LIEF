set(LIEF_VDEX_SRC
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.tcc
  ${CMAKE_CURRENT_LIST_DIR}/File.cpp
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
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/hash.hpp"

  ${CMAKE_CURRENT_LIST_DIR}/Structures.hpp
)

# JSON Public API: Always present
list(APPEND LIEF_VDEX_SRC       "${CMAKE_CURRENT_LIST_DIR}/json_api.cpp")
list(APPEND LIEF_VDEX_INC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/VDEX/json.hpp")

# JSON Impl
if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_VDEX_SRC       "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
  list(APPEND LIEF_VDEX_INC_FILES "${CMAKE_CURRENT_LIST_DIR}/json_internal.hpp")
endif()

source_group("Source Files\\VDEX" FILES ${LIEF_VDEX_SRC})
source_group("Header Files\\VDEX" FILES ${LIEF_VDEX_INC_FILES})

if (LIEF_VDEX)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_VDEX_SRC}
    ${LIEF_VDEX_INC_FILES}
  )
endif()
