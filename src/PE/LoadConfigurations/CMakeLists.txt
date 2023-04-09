
set(LIEF_PE_LOAD_CONFIGURATION_SRC
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurations.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfiguration.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfiguration.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV0.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV0.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV1.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV1.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV2.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV2.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV3.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV3.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV4.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV4.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV5.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV5.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV6.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV6.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV7.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV7.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV8.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV8.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV9.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV9.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV10.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV10.tcc"

  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV11.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/LoadConfigurationV11.tcc"
)


set(LIEF_PE_LOAD_CONFIGURATION_INCLUDE
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfiguration.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV0.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV1.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV2.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV3.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV4.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV5.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV6.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV7.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV8.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV9.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV10.hpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/PE/LoadConfigurations/LoadConfigurationV11.hpp"
)

source_group("Source Files\\PE\\Load Configure" FILES ${LIEF_PE_LOAD_CONFIGURATION_SRC})
source_group("Source Files\\PE\\Load Configure" FILES ${LIEF_PE_LOAD_CONFIGURATION_INCLUDE})

if (LIEF_PE)
  target_sources(LIB_LIEF PRIVATE
    ${LIEF_PE_LOAD_CONFIGURATION_SRC}
    ${LIEF_PE_LOAD_CONFIGURATION_INCLUDE}
  )
endif()

