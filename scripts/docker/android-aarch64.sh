#!/usr/bin/bash
set -ex
CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden '
CFLAGS='-ffunction-sections -fdata-sections'
export LDFLAGS='-Wl,--gc-sections -Wl,--exclude-libs,ALL'

ARCH_DIR="android-aarch64"

mkdir -p build/$ARCH_DIR/static-release && mkdir -p build/$ARCH_DIR/shared-release
pushd build/$ARCH_DIR/shared-release

cmake ../../.. -GNinja \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-Bdynamic -llog -Wl,-Bstatic" \
  -DCMAKE_LINK_WHAT_YOU_USE=on \
  -DBUILD_SHARED_LIBS=on \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=off \
  -DCMAKE_BUILD_TYPE=Release

ninja

popd
pushd build/$ARCH_DIR/static-release

cmake ../../.. -GNinja \
  -DCMAKE_LINK_WHAT_YOU_USE=on \
  -DBUILD_SHARED_LIBS=off \
  -DCMAKE_EXE_LINKER_FLAGS="-Wl,-Bdynamic -llog -lc -Wl,-Bstatic" \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=on \
  -DCMAKE_BUILD_TYPE=Release

ninja
popd

pushd build/$ARCH_DIR
cpack --config ../../cmake/cpack.config.cmake
popd

/bin/mv build/$ARCH_DIR/*.tar.gz build/
chown -R 1000:1000 build/$ARCH_DIR
