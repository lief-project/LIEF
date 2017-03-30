set(LIEF_PYTHON_MACHO_SRC
  ${CMAKE_CURRENT_LIST_DIR}/pyMachO.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pyDylibCommand.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pyBinary.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pyLoadCommand.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pySegmentCommand.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pyHeader.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pySection.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pyParser.cpp
  ${CMAKE_CURRENT_LIST_DIR}/objects/pySymbol.cpp
  ${CMAKE_CURRENT_LIST_DIR}/pyMachOStructures.cpp
)

target_include_directories(pyLIEF PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_MACHO_SRC})



