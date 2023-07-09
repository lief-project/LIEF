set(LIEF_PYTHON_DEX_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/init.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyEnums.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyUtils.cpp"
)

set(LIEF_PYTHON_DEX_HDR
  "${CMAKE_CURRENT_SOURCE_DIR}/pyDEX.hpp")

target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_DEX_SRC} ${LIEF_PYTHON_DEX_HDR})
add_subdirectory(objects)


