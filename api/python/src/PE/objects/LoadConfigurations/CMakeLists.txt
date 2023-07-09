set(LIEF_PYTHON_PE_LOAD_CONFIG_SRC
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfiguration.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV0.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV1.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV2.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV3.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV4.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV5.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV6.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV7.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV8.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV9.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV10.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/pyLoadConfigurationV11.cpp"
)

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_PE_LOAD_CONFIG_SRC}")
