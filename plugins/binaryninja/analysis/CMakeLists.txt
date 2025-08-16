add_library(analysis-core INTERFACE)

target_include_directories(analysis-core INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(src)

add_library(analysis-plugin SHARED src/plugin.cpp)

string(TOLOWER ${CMAKE_SYSTEM_NAME} CMAKE_SYSTEM_NAME_LOWER)
string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} CMAKE_SYSTEM_PROCESSOR_LOWER)

set_target_properties(analysis-plugin PROPERTIES
  PREFIX                    ""
  OUTPUT_NAME               lief-analysis-plugin-${CMAKE_SYSTEM_NAME_LOWER}-${CMAKE_SYSTEM_PROCESSOR_LOWER}
  VISIBILITY_INLINES_HIDDEN ON
  CXX_VISIBILITY_PRESET     hidden
  C_VISIBILITY_PRESET       hidden
)

target_link_libraries(analysis-plugin PUBLIC
  lief-binaryninja-libraries
  analysis-core
)

install(TARGETS analysis-plugin
  ARCHIVE DESTINATION lief-binaryninja
  LIBRARY DESTINATION lief-binaryninja
  RUNTIME DESTINATION lief-binaryninja)

add_subdirectory(tools)
