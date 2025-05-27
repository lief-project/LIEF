cmake_minimum_required(VERSION 3.24 FATAL_ERROR)
project(lief-jni CXX)

add_library(lief-jni SHARED jni.cpp)

target_include_directories(lief-jni PUBLIC
  ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(lief)

string(TOLOWER ${CMAKE_SYSTEM_NAME} CMAKE_SYSTEM_NAME_LOWER)
string(TOLOWER ${CMAKE_SYSTEM_PROCESSOR} CMAKE_SYSTEM_PROCESSOR_LOWER)

set_target_properties(lief-jni PROPERTIES
  PREFIX                    ""
  OUTPUT_NAME               lief-jni-${CMAKE_SYSTEM_NAME_LOWER}-${CMAKE_SYSTEM_PROCESSOR_LOWER}
  VISIBILITY_INLINES_HIDDEN ON
  CXX_VISIBILITY_PRESET     hidden
  C_VISIBILITY_PRESET       hidden
)

target_link_libraries(lief-jni PUBLIC
  lief-ghidra-libraries
)

install(TARGETS lief-jni
  ARCHIVE DESTINATION data
  LIBRARY DESTINATION data
  RUNTIME DESTINATION data)
