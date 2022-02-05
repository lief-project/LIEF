set(LIEF_PYTHON_OAT_OBJECTS_SRC
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyDexFile.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyClass.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyMethod.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBinary.cpp"
)

set(LIEF_PYTHON_OAT_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyOAT.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyEnums.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyUtils.cpp"
)


set(LIEF_PYTHON_OAT_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyOAT.hpp")


list(APPEND LIEF_PYTHON_OAT_SRC ${LIEF_PYTHON_OAT_OBJECTS_SRC})

source_group("Source Files\\OAT" FILES ${LIEF_PYTHON_OAT_SRC})
source_group("Header Files\\OAT" FILES ${LIEF_PYTHON_OAT_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_OAT_SRC}" "${LIEF_PYTHON_OAT_HDR}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_LIST_DIR}/../")


