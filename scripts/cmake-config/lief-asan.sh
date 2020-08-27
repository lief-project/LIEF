#!/bin/sh
cmake ..                                \
  -DLIEF_DOC=off                        \
  -DLIEF_PYTHON_API=off                 \
  -DLIEF_EXAMPLES=on                    \
  -DLIEF_C_API=on                       \
  -DLIEF_LOGGING=off                    \
  -DLIEF_ASAN=on                        \
  -CMAKE_CXX_COMPILER=g++               \
  -CMAKE_C_COMPILER=gcc                 \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
