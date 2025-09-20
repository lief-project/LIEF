# ------------------------------------------------------------------------------
# analysis-tool
# ------------------------------------------------------------------------------
add_executable(analysis-tool main.cpp)

set_target_properties(analysis-tool PROPERTIES
  PREFIX                    ""
  OUTPUT_NAME               lief-analysis-tool-${CMAKE_SYSTEM_NAME_LOWER}-${CMAKE_SYSTEM_PROCESSOR_LOWER}
  VISIBILITY_INLINES_HIDDEN ON
  CXX_VISIBILITY_PRESET     hidden
  C_VISIBILITY_PRESET       hidden
)

target_link_libraries(analysis-tool PUBLIC
  lief-binaryninja-libraries
  analysis-core
  binaryninja-api::binaryninjaapi
)

install(TARGETS analysis-tool
  ARCHIVE DESTINATION lief-binaryninja
  LIBRARY DESTINATION lief-binaryninja
  RUNTIME DESTINATION lief-binaryninja)


# ------------------------------------------------------------------------------
# diff-analysis-tool
# ------------------------------------------------------------------------------
add_executable(diff-analysis-tool diff-analysis.cpp)

set_target_properties(diff-analysis-tool PROPERTIES
  PREFIX                    ""
  OUTPUT_NAME               lief-diff-analysis-tool-${CMAKE_SYSTEM_NAME_LOWER}-${CMAKE_SYSTEM_PROCESSOR_LOWER}
  VISIBILITY_INLINES_HIDDEN ON
  CXX_VISIBILITY_PRESET     hidden
  C_VISIBILITY_PRESET       hidden
)

target_link_libraries(diff-analysis-tool PUBLIC
  lief-binaryninja-libraries
  analysis-core
  binaryninja-api::binaryninjaapi
)

install(TARGETS diff-analysis-tool
  ARCHIVE DESTINATION lief-binaryninja
  LIBRARY DESTINATION lief-binaryninja
  RUNTIME DESTINATION lief-binaryninja)

# ------------------------------------------------------------------------------
# create-bndb
# ------------------------------------------------------------------------------
add_executable(create-bndb create-bndb.cpp)

set_target_properties(create-bndb PROPERTIES
  PREFIX                    ""
  OUTPUT_NAME               lief-create-bndb-${CMAKE_SYSTEM_NAME_LOWER}-${CMAKE_SYSTEM_PROCESSOR_LOWER}
  VISIBILITY_INLINES_HIDDEN ON
  CXX_VISIBILITY_PRESET     hidden
  C_VISIBILITY_PRESET       hidden
)

target_link_libraries(create-bndb PUBLIC
  lief-binaryninja-libraries
  analysis-core
  binaryninja-api::binaryninjaapi
)

install(TARGETS create-bndb
  ARCHIVE DESTINATION lief-binaryninja
  LIBRARY DESTINATION lief-binaryninja
  RUNTIME DESTINATION lief-binaryninja)


# ------------------------------------------------------------------------------
# android-jni-typelib
# ------------------------------------------------------------------------------
add_executable(android-jni-typelib android-jni-typelib.cpp)

set_target_properties(android-jni-typelib PROPERTIES
  PREFIX                    ""
  OUTPUT_NAME               lief-android-jni-typelib-${CMAKE_SYSTEM_NAME_LOWER}-${CMAKE_SYSTEM_PROCESSOR_LOWER}
  VISIBILITY_INLINES_HIDDEN ON
  CXX_VISIBILITY_PRESET     hidden
  C_VISIBILITY_PRESET       hidden
)

target_link_libraries(android-jni-typelib PUBLIC
  lief-binaryninja-libraries
  analysis-core
  binaryninja-api::binaryninjaapi
)

install(TARGETS android-jni-typelib
  ARCHIVE DESTINATION lief-binaryninja
  LIBRARY DESTINATION lief-binaryninja
  RUNTIME DESTINATION lief-binaryninja)

