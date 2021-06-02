#!/usr/bin/sh
set -ex

mkdir -p build/osx-aarch64/static-release && mkdir -p build/osx-aarch64/shared-release
pushd build/osx-aarch64/shared-release

cmake ../../.. -GNinja \
  -DBUILD_SHARED_LIBS=on \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=off \
  -DCMAKE_BUILD_TYPE=Release

ninja


popd
pushd build/osx-aarch64/static-release

cmake ../../.. -GNinja \
  -DBUILD_SHARED_LIBS=off \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=on \
  -DCMAKE_BUILD_TYPE=Release

ninja

popd
pushd build/osx-aarch64
cpack --config ../../cmake/cpack.config.cmake
popd

/bin/mv build/osx-aarch64/*.tar.gz build/
