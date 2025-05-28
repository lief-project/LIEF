cmake_minimum_required(VERSION 3.24 FATAL_ERROR)
project(lief-ghidra-plugins CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(LIEF   REQUIRED)
find_package(spdlog REQUIRED)
find_package(JNI    REQUIRED)
find_package(ghidra-jni REQUIRED)

find_file(JNI_BIND "jni_bind.h"
  HINTS
    /jni-bind
    ${CMAKE_SOURCE_DIR}/jni-bind
    ${CMAKE_SOURCE_DIR}/../jni-bind
    ${CMAKE_SOURCE_DIR}/../../jni-bind
    ${CMAKE_CURRENT_SOURCE_DIR}/jni-bind
    ${CMAKE_CURRENT_SOURCE_DIR}/../jni-bind
    ${CMAKE_CURRENT_SOURCE_DIR}/../../jni-bind
    ${JNI_BIND_HINT}
  REQUIRED
)
cmake_path(GET JNI_BIND PARENT_PATH JNI_BIND_DIR)

add_library(lief-ghidra-libraries INTERFACE)

target_include_directories(lief-ghidra-libraries INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}

  ${JAVA_INCLUDE_PATH}
  ${JAVA_INCLUDE_PATH2}

  ${JNI_BIND_DIR}
)

target_link_libraries(lief-ghidra-libraries
  INTERFACE
  spdlog::spdlog
  LIEF::LIEF
  ghidra::ghidra-jni
  ${JAVA_JVM_LIBRARY}
)

add_subdirectory(jni)
