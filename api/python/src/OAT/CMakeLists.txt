set(LIEF_PYTHON_OAT_SRC
  "${CMAKE_CURRENT_LIST_DIR}/init.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyEnums.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyUtils.cpp"
)

set(LIEF_PYTHON_OAT_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyOAT.hpp")

target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_OAT_SRC} ${LIEF_PYTHON_OAT_HDR})
add_subdirectory(objects)


