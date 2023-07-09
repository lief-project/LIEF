set(LIEF_PYTHON_ELF_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/init.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/enums.cpp"
)

set(LIEF_PYTHON_ELF_HDR
  "${CMAKE_CURRENT_SOURCE_DIR}/pyELF.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/init.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/enums.hpp"
)

source_group("Source Files\\ELF" FILES ${LIEF_PYTHON_ELF_SRC})
source_group("Header Files\\ELF" FILES ${LIEF_PYTHON_ELF_HDR})

target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_ELF_SRC} ${LIEF_PYTHON_ELF_HDR})

add_subdirectory(objects)
