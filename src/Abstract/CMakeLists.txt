set(LIEF_ABSTRACT_SRC
  "${CMAKE_CURRENT_LIST_DIR}/Binary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Symbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/EnumToString.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Header.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Section.tcc"
  "${CMAKE_CURRENT_LIST_DIR}/Parser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Relocation.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/Function.cpp"

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
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Relocation.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/Function.hpp"
)

# JSON Public API: Always present
list(APPEND LIEF_ABSTRACT_SRC       "${CMAKE_CURRENT_LIST_DIR}/json_api.cpp")
list(APPEND LIEF_ABSTRACT_INC_FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/Abstract/json.hpp")

# JSON Impl
if (LIEF_ENABLE_JSON)
  list(APPEND LIEF_ABSTRACT_SRC       "${CMAKE_CURRENT_LIST_DIR}/json.cpp")
  list(APPEND LIEF_ABSTRACT_INC_FILES "${CMAKE_CURRENT_LIST_DIR}/json_internal.hpp")
endif()


source_group("Source Files\\Abstract" FILES ${LIEF_ABSTRACT_SRC})
source_group("Header Files\\Abstract" FILES ${LIEF_ABSTRACT_INCLUDE_FILES})

target_sources(LIB_LIEF PRIVATE
  ${LIEF_ABSTRACT_SRC}
  ${LIEF_ABSTRACT_INCLUDE_FILES})
