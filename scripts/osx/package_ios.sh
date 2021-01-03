#!/usr/bin/sh
set -ex

ARCH_DIR="ios-aarch64"

mkdir -p build/$ARCH_DIR/static-release && mkdir -p build/$ARCH_DIR/shared-release
pushd build/$ARCH_DIR/shared-release

cmake ../../.. -GNinja \
  -DCMAKE_TOOLCHAIN_FILE=../../../cmake/ios.toolchain.cmake \
  -DBUILD_SHARED_LIBS=on \
  -DENABLE_BITCODE=0 \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=off \
  -DCMAKE_BUILD_TYPE=Release

ninja


popd
pushd build/$ARCH_DIR/static-release

cmake ../../.. -GNinja \
  -DCMAKE_TOOLCHAIN_FILE=../../../cmake/ios.toolchain.cmake \
  -DBUILD_SHARED_LIBS=off \
  -DENABLE_BITCODE=0 \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=on \
  -DCMAKE_BUILD_TYPE=Release

ninja

popd
pushd build/$ARCH_DIR
cpack --config ../../cmake/cpack.config.cmake
popd

/bin/mv build/$ARCH_DIR/*.tar.gz build/
