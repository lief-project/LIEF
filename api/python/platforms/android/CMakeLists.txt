set(LIEF_PYTHON_ANDROID_SRC
  "${CMAKE_CURRENT_LIST_DIR}/pyAndroid.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/pyVersion.cpp"
)

set(LIEF_PYTHON_ANDROID_HDR
  "${CMAKE_CURRENT_LIST_DIR}/pyAndroid.hpp")

source_group("Source Files\\Android" FILES ${LIEF_PYTHON_ANDROID_SRC})
source_group("Header Files\\Android" FILES ${LIEF_PYTHON_ANDROID_HDR})

target_sources(pyLIEF PRIVATE "${LIEF_PYTHON_ANDROID_SRC}" "${LIEF_PYTHON_ANDROID_HDR}")
target_include_directories(pyLIEF PUBLIC "${CMAKE_CURRENT_LIST_DIR}" "${CMAKE_CURRENT_LIST_DIR}/../../")

