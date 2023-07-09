set(LIEF_PYTHON_PE_SIG_ATTR_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pyMsCounterSign.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyContentType.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyGenericType.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySpcSpOpusInfo.cpp"

  "${CMAKE_CURRENT_SOURCE_DIR}/pyMsSpcStatementType.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyMsSpcNestedSignature.cpp"

  "${CMAKE_CURRENT_SOURCE_DIR}/pyPKCS9SigningTime.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyPKCS9MessageDigest.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyPKCS9AtSequenceNumber.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyPKCS9CounterSignature.cpp"
)

target_sources(pyLIEF PRIVATE ${LIEF_PYTHON_PE_SIG_ATTR_SRC})
