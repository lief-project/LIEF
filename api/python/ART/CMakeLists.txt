set(LIEF_PYTHON_ART_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyART.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyEnums.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyUtils.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyFile.cpp"
)

set(LIEF_PYTHON_ART_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyART.hpp")

source_group("Source Files\\ART" FILES ${LIEF_PYTHON_ART_SRC})
source_group("Header Files\\ART" FILES ${LIEF_PYTHON_ART_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_ART_SRC}" "${LIEF_PYTHON_ART_HDR}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_LIST_DIR}/../")


