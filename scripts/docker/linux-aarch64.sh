#!/usr/bin/bash
set -ex

# Script to be run with liefproject/manylinux2014-aarch64:
# ==============================================================================================
# docker run \
#  -e CCACHE_DIR=/ccache \
#  -v $LIEF_SRC:/work \
#  -v $HOME/.ccache:/ccache \
#  --rm liefproject/manylinux2014-aarch64 bash /work/scripts/docker/linux-aarch64.sh
# ==============================================================================================
#

CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc -static-libstdc++'
CFLAGS='-ffunction-sections -fdata-sections -static-libgcc -static-libstdc++'
export LDFLAGS='-Wl,--gc-sections -Wl,--exclude-libs,ALL'

ARCH_DIR="linux-aarch64"

mkdir -p build/$ARCH_DIR/static-release && mkdir -p build/$ARCH_DIR/shared-release
pushd build/$ARCH_DIR/shared-release

cmake ../../.. -GNinja \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_LINK_WHAT_YOU_USE=on \
  -DBUILD_SHARED_LIBS=on \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=off \
  -DCMAKE_BUILD_TYPE=Release

ninja

popd
pushd build/$ARCH_DIR/static-release

cmake ../../.. -GNinja \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_LINK_WHAT_YOU_USE=on \
  -DBUILD_SHARED_LIBS=off \
  -DLIEF_PYTHON_API=off \
  -DLIEF_INSTALL_COMPILED_EXAMPLES=on \
  -DCMAKE_BUILD_TYPE=Release

ninja

popd

pushd build/$ARCH_DIR
cpack --config ../../cmake/cpack.config.cmake
popd

/bin/mv build/$ARCH_DIR/*.tar.gz build/

chown -R 1000:1000 build/
