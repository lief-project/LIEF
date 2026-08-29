include(FetchContent)

set(CATCH_VERSION 3.15.3)
set(CATCH_SHA256 SHA256=d36d45ec0dbc3d26936dfab665695f08eed87c253d12546c135074273e89b755)
set(CATCH_URL "${THIRD_PARTY_DIRECTORY}/Catch2-${CATCH_VERSION}.zip" CACHE STRING "URL to the Catch")

set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

FetchContent_Declare(Catch2
  URL            ${CATCH_URL}
  URL_HASH       ${CATCH_SHA256}
)
FetchContent_MakeAvailable(Catch2)

add_executable(unittests
  main.cpp
  utils.cpp
  test_iterators.cpp
  test_enums.cpp
  test_utils.cpp
  test_hash.cpp
  test_binarystream.cpp
  test_iostream.cpp
  test_pe.cpp
  test_elf.cpp
  test_oat.cpp
  test_linux_header.cpp
  test_parser_api.cpp
)

if (NOT BUILD_SHARED_LIBS)
  target_sources(unittests PRIVATE test_macho.cpp)
endif()

if (LIEF_RUNTIME AND LIEF_RUNTIME_PLATFORM_LINUX)
  target_sources(unittests PRIVATE test_runtime_linux.cpp)
endif()

target_precompile_headers(unittests PRIVATE pch.hpp)

set_target_properties(unittests
  PROPERTIES CXX_STANDARD           17
             CXX_STANDARD_REQUIRED  ON)

target_link_libraries(unittests LIB_LIEF Catch2::Catch2WithMain)

add_test(unittests
         ${CMAKE_CURRENT_BINARY_DIR}/unittests)
