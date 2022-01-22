#!/bin/sh
cmake -GNinja ..                                \
  -DLIEF_DOC=off                        \
  -DLIEF_PYTHON_API=off                 \
  -DLIEF_EXAMPLES=on                   \
  -DLIEF_C_API=off                      \
  -DLIEF_PE=off                         \
  -DLIEF_MACHO=off                      \
  -DLIEF_OAT=off                        \
  -DLIEF_DEX=off                        \
  -DLIEF_VDEX=off                       \
  -DLIEF_ART=off                        \
  -DLIEF_LOGGING_DEBUG=on               \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
