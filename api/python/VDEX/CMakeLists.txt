set(LIEF_PYTHON_VDEX_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyVDEX.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyUtils.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyFile.cpp"
)

set(LIEF_PYTHON_VDEX_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyVDEX.hpp")

source_group("Source Files\\VDEX" FILES ${LIEF_PYTHON_VDEX_SRC})
source_group("Header Files\\VDEX" FILES ${LIEF_PYTHON_VDEX_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_VDEX_SRC}" "${LIEF_PYTHON_VDEX_HDR}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_LIST_DIR}/../")


