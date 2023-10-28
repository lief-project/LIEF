#!/usr/bin/sh
set -ex
cmake -B ${BUILD_DIR} -S ${SRC_DIR} -GNinja \
      -DLIEF_USE_CCACHE=off \
      -DCMAKE_CXX_COMPILER=/usr/bin/clang++ -DCMAKE_C_COMPILER=/usr/bin/clang
ninja -C ${BUILD_DIR} LIB_LIEF
