cmake_minimum_required(VERSION 3.24)

project(lief-rust-ffi)

option(INSTALL_LIEF_CORE "Whether the libLIEF library should be installed along with lief-sys" ON)

if (NOT DEFINED LIEF_RUST_FFI_SRC)
  message(FATAL_ERROR "'LIEF_RUST_FFI_SRC' is not set")
endif()

find_package(LIEF REQUIRED)

message(STATUS "Rust FFI source: ${LIEF_RUST_FFI_SRC}")

file(GLOB_RECURSE LIEF_SYS_GENERATED_SRC
  CONFIGURE_DEPENDS
  ${LIEF_RUST_FFI_SRC}/*.cpp
)

add_library(lief-sys STATIC
  ${LIEF_SYS_GENERATED_SRC}

  rust_cpp_bridge.cpp
)

set_target_properties(lief-sys PROPERTIES
  POSITION_INDEPENDENT_CODE    ON
  CXX_STANDARD                 17
  CXX_STANDARD_REQUIRED        ON
  CXX_VISIBILITY_PRESET        hidden
  C_VISIBILITY_PRESET          hidden
  OUTPUT_NAME                  "lief-sys"
)

target_compile_options(lief-sys PRIVATE
  -O3
  -fno-rtti -fno-exceptions
  -ffunction-sections -fdata-sections
  -fvisibility=hidden -fvisibility-inlines-hidden
)

get_property(LIEF_LIB_LOCATION TARGET LIEF::LIEF PROPERTY LOCATION)
install(TARGETS lief-sys
        LIBRARY DESTINATION lib/
        ARCHIVE DESTINATION lib/
        RUNTIME DESTINATION lib/
)

if (INSTALL_LIEF_CORE)
  install(FILES ${LIEF_LIB_LOCATION} DESTINATION lib/)
endif()

target_include_directories(lief-sys PUBLIC
  ${LIEF_RUST_FFI_SRC}
  ${LIEF_INCLUDE_DIRS}
)
