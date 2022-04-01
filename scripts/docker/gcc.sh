#!/usr/bin/sh
set -ex
cmake -B ${BUILD_DIR} -S ${SRC_DIR} -GNinja \
      -DLIEF_USE_CCACHE=off \
      -DCMAKE_CXX_COMPILER=/usr/bin/g++-11 -DCMAKE_C_COMPILER=/usr/bin/gcc-11
ninja -C ${BUILD_DIR} LIB_LIEF
