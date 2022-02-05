set(LIEF_ART_SRC
  ${CMAKE_CURRENT_LIST_DIR}/Parser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Parser.tcc
  ${CMAKE_CURRENT_LIST_DIR}/File.cpp
  ${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Header.tcc
  ${CMAKE_CURRENT_LIST_DIR}/utils.cpp
  ${CMAKE_CURRENT_LIST_DIR}/Structures.cpp
  ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
)

set(LIEF_ART_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/File.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/types.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/utils.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/java_structures.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/hash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/enums.hpp"
  "${CMAKE_CURRENT_LIST_DIR}/Structures.hpp"

)

# JSON Public API: Always present
list(APPEND LIEF_ART_SRC       "${CMAKE_CURRENT_LIST_DIR}/json_api.cpp")
list(APPEND LIEF_ART_INC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/ART/json.hpp")

# JSON Impl
if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_ART_SRC       "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
  list(APPEND LIEF_ART_INC_FILES "${CMAKE_CURRENT_LIST_DIR}/json_internal.hpp")
endif()

source_group("Source Files\\ART" FILES ${LIEF_ART_SRC})
source_group("Header Files\\ART" FILES ${LIEF_ART_INC_FILES})

if (LIEF_ART)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_ART_SRC}
    ${LIEF_ART_INC_FILES}
  )
endif()
