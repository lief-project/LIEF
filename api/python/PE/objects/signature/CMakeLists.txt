set(LIEF_PYTHON_PE_SIG_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pySignerInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyAttribute.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyRsaInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyx509.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyContentInfo.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pySignature.cpp"
)

source_group("Header Files\\PE\\signature" FILES ${LIEF_PYTHON_PE_SIG_SRC})

target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_PE_SIG_SRC})

include("${CMAKE_CURRENT_LIST_DIR}/attributes/CMakeLists.txt")
