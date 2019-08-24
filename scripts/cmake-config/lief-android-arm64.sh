#!/bin/sh
cmake ..                                \
  -DLIEF_DOC=off                        \
  -DLIEF_PYTHON_API=off                 \
  -DLIEF_EXAMPLES=off                   \
  -DLIEF_C_API=off                      \
  -DLIEF_PE=off                         \
  -DLIEF_MACHO=off                      \
  -DLIEF_OAT=off                        \
  -DLIEF_DEX=off                        \
  -DLIEF_VDEX=off                       \
  -DLIEF_ART=off                        \
  -DLIEF_LOGGING=off                    \
  -DANDROID_ABI="arm64-v8a"           \
  -DANDROID_PLATFORM=android-24         \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/install \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo     \
  -DCMAKE_TOOLCHAIN_FILE=${ANDROID_SDK}/ndk-bundle/build/cmake/android.toolchain.cmake
