#!/usr/bin/sh
set -ex

mkdir -p build/osx-x86-64/static-release && mkdir -p build/osx-x86-64/shared-release
mkdir -p build/osx-aarch64/static-release && mkdir -p build/osx-aarch64/shared-release

# ================================================

cmake -B build/osx-x86-64/shared-release -GNinja  \
  -DBUILD_SHARED_LIBS=on                          \
  -DLIEF_PYTHON_API=off                           \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=off            \
  -DCMAKE_BUILD_TYPE=Release

cmake -B build/osx-x86-64/static-release -GNinja  \
  -DBUILD_SHARED_LIBS=off                         \
  -DLIEF_PYTHON_API=off                           \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=on             \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/install/x64       \
  -DCMAKE_BUILD_TYPE=Release

# ================================================

cmake -B build/osx-aarch64/shared-release -GNinja \
  -DCMAKE_OSX_ARCHITECTURES=arm64                 \
  -DBUILD_SHARED_LIBS=on                          \
  -DLIEF_PYTHON_API=off                           \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=off            \
  -DCMAKE_BUILD_TYPE=Release

cmake -B build/osx-aarch64/static-release -GNinja \
  -DCMAKE_OSX_ARCHITECTURES=arm64                 \
  -DBUILD_SHARED_LIBS=off                         \
  -DLIEF_PYTHON_API=off                           \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=on             \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/install/arm64     \
  -DCMAKE_BUILD_TYPE=Release

# ================================================

cmake --build build/osx-x86-64/shared-release --target all
cmake --build build/osx-x86-64/static-release --target install

cmake --build build/osx-aarch64/shared-release --target all
cmake --build build/osx-aarch64/static-release --target install

pushd build/osx-x86-64
cpack --config ../../cmake/cpack.config.cmake
popd

pushd build/osx-aarch64
cpack --config ../../cmake/cpack.config.cmake
popd

/bin/mv build/osx-aarch64/*.tar.gz build/
/bin/mv build/osx-x86-64/*.tar.gz build/
ls -alh build
