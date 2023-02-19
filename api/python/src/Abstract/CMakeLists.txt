
set(LIEF_PYTHON_ABSTRACT_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyAbstract.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyBinary.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySection.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pySymbol.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyRelocation.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/objects/pyFunction.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyEnums.cpp"
)


set(LIEF_PYTHON_ABSTRACT_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyAbstract.hpp"
)

source_group("Source Files\\Abstract" FILES ${LIEF_PYTHON_ABSTRACT_SRC})
source_group("Header Files\\Abstract" FILES ${LIEF_PYTHON_ABSTRACT_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_ABSTRACT_SRC}" "${LIEF_PYTHON_ABSTRACT_HDR}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}")


