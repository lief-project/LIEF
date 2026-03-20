if(__lief_runtime)
  return()
endif()
set(__lief_runtime ON)

set(LIEF_RUNTIME_SUPPORTED_PLATFORMS "linux" "windows" "android" "ios" "osx")
set(LIEF_RUNTIME_SUPPORTED_ARCH "x86_64" "arm64")

set(LIEF_RUNTIME_PLATFORM_LINUX 0)
set(LIEF_RUNTIME_PLATFORM_WINDOWS 0)
set(LIEF_RUNTIME_PLATFORM_ANDROID 0)
set(LIEF_RUNTIME_PLATFORM_OSX 0)
set(LIEF_RUNTIME_PLATFORM_IOS 0)

set(LIEF_RUNTIME_ARCH_ARM64 0)
set(LIEF_RUNTIME_ARCH_X86_64 0)

if(NOT DEFINED LIEF_RUNTIME_PLATFORM)
  message(FATAL_ERROR
    "'LIEF_RUNTIME_PLATFORM' is not set.\n  Supported platforms: ${LIEF_RUNTIME_SUPPORTED_PLATFORMS}"
  )
endif()

if (LIEF_RUNTIME_PLATFORM STREQUAL "linux")
  set(LIEF_RUNTIME_PLATFORM_LINUX 1)
elseif (LIEF_RUNTIME_PLATFORM STREQUAL "windows")
  set(LIEF_RUNTIME_PLATFORM_WINDOWS 1)
elseif (LIEF_RUNTIME_PLATFORM STREQUAL "osx")
  set(LIEF_RUNTIME_PLATFORM_OSX 1)
elseif (LIEF_RUNTIME_PLATFORM STREQUAL "ios")
  set(LIEF_RUNTIME_PLATFORM_IOS 1)
elseif (LIEF_RUNTIME_PLATFORM STREQUAL "android")
  set(LIEF_RUNTIME_PLATFORM_ANDROID 1)
else()
  message(FATAL_ERROR
    "'${LIEF_RUNTIME_PLATFORM}' is not a valid platform.\n  Supported platforms: ${LIEF_RUNTIME_SUPPORTED_PLATFORMS}"
  )
endif()

if(NOT DEFINED LIEF_RUNTIME_ARCH)
  message(
    FATAL_ERROR
      "'LIEF_RUNTIME_ARCH' is not set.\n  Supported architectures: ${LIEF_RUNTIME_SUPPORTED_ARCH}"
  )
endif()

if (LIEF_RUNTIME_ARCH STREQUAL "x86_64")
  set(LIEF_RUNTIME_ARCH_X86_64 1)
elseif (LIEF_RUNTIME_ARCH STREQUAL "arm64")
  set(LIEF_RUNTIME_ARCH_ARM64 1)
else()
  message(FATAL_ERROR
    "'${LIEF_RUNTIME_ARCH_ARM64}' is not a valid architecture.\n  Supported platforms: ${LIEF_RUNTIME_SUPPORTED_ARCH}"
  )
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/LIEF/runtime/config.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/runtime/config.h" @ONLY)
