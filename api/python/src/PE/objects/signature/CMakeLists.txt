set(LIEF_PYTHON_PE_SIG_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pySignerInfo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyAttribute.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyRsaInfo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyx509.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyContentInfo.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyGenericContent.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySpcIndirectData.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySignature.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pySpcIndirectData.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyGenericContent.cpp"
)

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_PE_SIG_SRC}")
add_subdirectory(attributes)
