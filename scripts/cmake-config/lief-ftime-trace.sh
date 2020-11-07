#!/bin/sh
# Generate timing report and process the output with ClangBuildAnalyzer (https://github.com/aras-p/ClangBuildAnalyzer)
# - mkdir build_time_trace && sh ../scripts/cmake-config/lief-ftime-trace.sh
# - make -j8 LIB_LIEF
# - ClangBuildAnalyzer --all CMakeFiles/LIB_LIEF.dir/src build_analyzer.data
# - ClangBuildAnalyzer --analyze build_analyzer.data|& tee build_analyzer.log

cmake ..                                \
  -DLIEF_USE_CCACHE=off                 \
  -DLIEF_DOC=off                        \
  -DLIEF_PYTHON_API=off                 \
  -DLIEF_EXAMPLES=on                    \
  -DLIEF_C_API=on                       \
  -DLIEF_LOGGING=off                    \
  -DLIEF_ASAN=off                       \
  -DCMAKE_CXX_FLAGS=-ftime-trace        \
  -DCMAKE_C_FLAGS=-ftime-trace          \
  -DCMAKE_CXX_COMPILER=clang++          \
  -DCMAKE_C_COMPILER=clang              \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
