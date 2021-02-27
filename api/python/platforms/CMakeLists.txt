set(LIEF_PYTHON_PLATFORM_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyPlatform.cpp"
)

set(LIEF_PYTHON_PLATFORM_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyPlatform.hpp")

source_group("Source Files\\Platform" FILES ${LIEF_PYTHON_PLATFORM_SRC})
source_group("Header Files\\Platform" FILES ${LIEF_PYTHON_PLATFORM_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_PLATFORM_HDR}" "${LIEF_PYTHON_PLATFORM_SRC}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_LIST_DIR}/../")

include("${CMAKE_CURRENT_LIST_DIR}/android/CMakeLists.txt")
