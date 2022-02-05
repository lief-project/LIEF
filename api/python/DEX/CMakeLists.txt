set(LIEF_PYTHON_DEX_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyDEX.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyEnums.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyUtils.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyFile.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyClass.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyField.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyMethod.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyCodeInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyMapList.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyMapItem.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyType.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyPrototype.cpp"
)

set(LIEF_PYTHON_DEX_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyDEX.hpp")

source_group("Source Files\\DEX" FILES ${LIEF_PYTHON_DEX_SRC})
source_group("Header Files\\DEX" FILES ${LIEF_PYTHON_DEX_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_DEX_SRC}" "${LIEF_PYTHON_DEX_HDR}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_LIST_DIR}/../")


