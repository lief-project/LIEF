cmake_minimum_required(VERSION 3.24 FATAL_ERROR)
project(lief-binaryninja-plugins CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(LIEF               REQUIRED)
find_package(fmt                REQUIRED)
find_package(spdlog             REQUIRED)
find_package(binaryninja-api    REQUIRED)
find_package(binaryninja-logger REQUIRED)

add_library(lief-binaryninja-libraries INTERFACE)

target_include_directories(lief-binaryninja-libraries INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(lief-binaryninja-libraries
  INTERFACE
  fmt::fmt
  binaryninja-api::binaryninjaapi
  binaryninja-logger::binaryninja-logger
  spdlog::spdlog
  LIEF::LIEF
)

target_compile_definitions(lief-binaryninja-libraries INTERFACE
  BN_VERSION_MAJOR=${BN_VERSION_MAJOR}
  BN_VERSION_MINOR=${BN_VERSION_MINOR}
  BN_VERSION_PATCH=${BN_VERSION_PATCH}
)

add_subdirectory(dwarf-export)
