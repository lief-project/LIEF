set(LIEF_PYTHON_PE_SIG_ATTR_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyMsCounterSign.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyContentType.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyGenericType.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pySpcSpOpusInfo.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/pyMsSpcStatementType.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyMsSpcNestedSignature.cpp"

  "${CMAKE_CURRENT_LIST_DIR}/pyPKCS9SigningTime.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyPKCS9MessageDigest.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyPKCS9AtSequenceNumber.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyPKCS9CounterSignature.cpp"
)

source_group("Header Files\\PE\\signature\\attributes" FILES ${LIEF_PYTHON_PE_SIG_ATTR_SRC})

target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}")
target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_PE_SIG_ATTR_SRC})
