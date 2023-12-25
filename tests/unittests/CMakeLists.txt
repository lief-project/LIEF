include(FetchContent)

set(CATCH_VERSION 3.3.2)
set(CATCH_SHA256 SHA256=802a1d7f98f8e38a7913b596c5e3356ea76c544acb7c695bfd394544556359f3)
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
)

set_target_properties(unittests
  PROPERTIES CXX_STANDARD           17
             CXX_STANDARD_REQUIRED  ON)

target_link_libraries(unittests LIB_LIEF Catch2)

add_test(unittests
         ${CMAKE_CURRENT_BINARY_DIR}/unittests)
