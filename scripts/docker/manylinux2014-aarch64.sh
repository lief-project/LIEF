#!/usr/bin/bash
set -ex
CXXFLAGS='-static-libgcc -static-libstdc++' \
$PYTHON_BINARY setup.py --ninja \
  build -t /tmp bdist_wheel \
  --plat-name manylinux2014_aarch64 \
  chown -R 1000:1000 /work/dist && \
  chown -R 1000:1000 /work/build
