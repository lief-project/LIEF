
set(LIEF_ANDROID_SRC
  ${CMAKE_CURRENT_LIST_DIR}/version.cpp
)

set(LIEF_ANDROID_INC_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/platforms/android/version.hpp"
)

source_group("Source Files\\Platforms\\Android" FILES ${LIEF_ANDROID_SRC})
source_group("Header Files\\Platforms\\Android" FILES ${LIEF_ANDROID_INC_FILES})

target_sources(LIB_LIEF PRIVATE
  ${LIEF_ANDROID_SRC}
  ${LIEF_ANDROID_INC_FILES}
)
