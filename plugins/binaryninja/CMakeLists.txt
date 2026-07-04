cmake_minimum_required(VERSION 3.24 FATAL_ERROR)
project(lief-binaryninja-plugins CXX)

include(CMakeDependentOption)

option(LIEF_BINARYNINJA_STATIC OFF)
option(LIEF_BINARYNINJA_CLANG_TIDY "Enable clang-tidy checks" OFF)

cmake_dependent_option(LIEF_BINARYNINJA_CLANG_TIDY_WARN_ERR
  "Enable WarningsAsErrors when running clang-tidy" OFF
  "LIEF_BINARYNINJA_CLANG_TIDY" OFF)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LIEF_BINARYNINJA_EXTRA_FLAGS)

find_package(LIEF               REQUIRED)
find_package(fmt                REQUIRED)
find_package(spdlog             REQUIRED)
find_package(binaryninja-api    REQUIRED)
find_package(binaryninja-logger REQUIRED)

project(lief-binaryninja-plugins VERSION
        ${LIEF_VERSION_MAJOR}.${LIEF_VERSION_MINOR}.${LIEF_VERSION_PATCH})

add_library(lief-binaryninja-libraries STATIC)

target_include_directories(lief-binaryninja-libraries PUBLIC
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>"
  "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_link_libraries(lief-binaryninja-libraries
  PUBLIC
  fmt::fmt
  binaryninja-api::binaryninjaapi
  binaryninja-logger::binaryninja-logger
  spdlog::spdlog
  LIEF::LIEF
)

target_compile_definitions(lief-binaryninja-libraries PUBLIC
  BN_VERSION_MAJOR=${BN_VERSION_MAJOR}
  BN_VERSION_MINOR=${BN_VERSION_MINOR}
  BN_VERSION_PATCH=${BN_VERSION_PATCH}
)

if (LIEF_BINARYNINJA_EXTRA_FLAGS)
  target_compile_options(lief-binaryninja-libraries PUBLIC
    ${LIEF_BINARYNINJA_EXTRA_FLAGS})
endif()

if (LIEF_BINARYNINJA_CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES "clang-tidy" REQUIRED)
  set(CLANG_TIDY_COMMAND
    "${CLANG_TIDY_EXE}"
    "--use-color"
    "--config-file=${CMAKE_CURRENT_SOURCE_DIR}/.clang-tidy-core.yaml"
  )
  if (LIEF_BINARYNINJA_CLANG_TIDY_WARN_ERR)
    list(APPEND CLANG_TIDY_COMMAND "--warnings-as-errors=*")
  endif()

  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")
endif()

add_subdirectory(src)
add_subdirectory(dwarf-export)
add_subdirectory(analysis)

if(LIEF_BINARYNINJA_STATIC)
  set(project_config_in "${CMAKE_CURRENT_LIST_DIR}/cmake/lief-binaryninja-config.cmake.in")
  set(project_config_out "${CMAKE_CURRENT_BINARY_DIR}/lief-binaryninja-config.cmake")
  set(config_targets_file "lief-binaryninja-config-targets.cmake")
  set(version_config_file "${CMAKE_CURRENT_BINARY_DIR}/lief-binaryninja-config-version.cmake")
  set(export_dest_dir "${CMAKE_INSTALL_LIBDIR}/cmake/lief-binaryninja")

  ## ---------------------------------------------------------------------------------------
  ## Include files
  ## ---------------------------------------------------------------------------------------
  install(
    DIRECTORY
      include/
      dwarf-export/include/
      analysis/include/
    DESTINATION
      "${CMAKE_INSTALL_INCLUDEDIR}"
  )

  install(
      TARGETS dwarf-core analysis-core lief-binaryninja-libraries
      EXPORT lief-binaryninja
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

  ## ---------------------------------------------------------------------------------------
  ## Install CMake config files
  ## ---------------------------------------------------------------------------------------
  export(
    TARGETS
      dwarf-core analysis-core
      lief-binaryninja-libraries
    NAMESPACE
      lief-binaryninja::
    FILE
      "${CMAKE_CURRENT_BINARY_DIR}/${config_targets_file}"
  )

  install(EXPORT lief-binaryninja DESTINATION ${export_dest_dir}
          NAMESPACE lief-binaryninja:: FILE ${config_targets_file})

  include(CMakePackageConfigHelpers)
  configure_package_config_file("${project_config_in}" "${project_config_out}"
                                INSTALL_DESTINATION ${export_dest_dir})

  write_basic_package_version_file("${version_config_file}" COMPATIBILITY SameMajorVersion)
  install(FILES "${project_config_out}" "${version_config_file}" DESTINATION "${export_dest_dir}")
else()
  install(DIRECTORY typelib DESTINATION lief-binaryninja)
endif()
