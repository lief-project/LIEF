set(LIEF_ABSTRACT_SRC
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/Parser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Relocation.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/hash.cpp"
)

set(LIEF_ABSTRACT_INCLUDE_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Binary.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Symbol.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/EnumToString.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Header.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Section.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Parser.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/enums.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/hash.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/type_traits.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Relocation.hpp"
)

# JSON Part
# =========
set(LIEF_ABSTRACT_JSON_SRC "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
set(LIEF_ABSTRACT_JSON_HDR "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/json.hpp")

if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_ABSTRACT_SRC           ${LIEF_ABSTRACT_JSON_SRC})
  list(APPEND LIEF_ABSTRACT_INCLUDE_FILES ${LIEF_ABSTRACT_JSON_HDR})
endif()

source_group("Source Files\\Abstract" FILES ${LIEF_ABSTRACT_SRC})
source_group("Header Files\\Abstract" FILES ${LIEF_ABSTRACT_INCLUDE_FILES})

target_sources(LIB_LIEF_STATIC PRIVATE
  ${LIEF_ABSTRACT_SRC}
  ${LIEF_ABSTRACT_INCLUDE_FILES})

target_sources(LIB_LIEF_SHARED PRIVATE
  ${LIEF_ABSTRACT_SRC}
  ${LIEF_ABSTRACT_INCLUDE_FILES})
