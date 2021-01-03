#!/usr/bin/sh
set -ex
cmake .. \
  -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/ios.toolchain.cmake \
  -DLIEF_PYTHON_API=off \
  -DPLATFORM=OS64 \
  -DBUILD_SHARED_LIBS=off \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/install

#cmake --build . --config Release --target install
