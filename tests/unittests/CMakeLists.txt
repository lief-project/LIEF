include(FetchContent)

set(CATCH_VERSION 3.12.0)
set(CATCH_SHA256 SHA256=e1e1592dbc971d9196b379aef1882f7d427ceaf0ecf6cae40b575d580dd83648)
set(CATCH_URL "${THIRD_PARTY_DIRECTORY}/Catch2-${CATCH_VERSION}.zip" CACHE STRING "URL to the Catch")

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
  test_macho.cpp
  test_linux_header.cpp
)

set_target_properties(unittests
  PROPERTIES CXX_STANDARD           17
             CXX_STANDARD_REQUIRED  ON)

target_link_libraries(unittests LIB_LIEF Catch2)

add_test(unittests
         ${CMAKE_CURRENT_BINARY_DIR}/unittests)
