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
  "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/utils.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/test_iterators.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/test_enums.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/test_utils.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/test_hash.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/test_binarystream.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/test_pe.cpp"
)

set_target_properties(unittests
  PROPERTIES CXX_STANDARD           17
             CXX_STANDARD_REQUIRED  ON)

target_link_libraries(unittests LIB_LIEF Catch2)

add_test(unittests
         ${CMAKE_CURRENT_BINARY_DIR}/unittests)
