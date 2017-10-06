set(LIEF_PYTHON_PE_LOAD_CONFIGURE_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfiguration.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV0.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV1.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV2.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV3.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV4.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV5.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV6.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyLoadConfigurationV7.cpp"
)

source_group("Source Files\\PE\\Load Configuration" FILES ${LIEF_PYTHON_PE_LOAD_CONFIGURE_SRC})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_PE_LOAD_CONFIGURE_SRC}")



