#!/usr/bin/bash

# Script to be run with liefproject/manylinux2014-aarch64. Example with Python 3.9:
# ==============================================================================================
# docker run \
#  -e CCACHE_DIR=/ccache \
#  -e PYTHON_BINARY=/opt/python/cp39-cp39/bin/python3.9 \
#  -v $LIEF_SRC:/work \
#  -v $HOME/.ccache:/ccache \
#  --rm liefproject/manylinux2014-aarch64 bash /work/scripts/docker/manylinux2014-aarch64.sh
# ==============================================================================================
# --lief-no-elf --lief-no-android --lief-no-macho --lief-no-json --lief-no-logging \
#
set -ex

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libstdc++ -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libstdc++ -static-libgcc'
export LDFLAGS='-Wl,--gc-sections -Wl,--exclude-libs,ALL'
LIEF_PY_XARCH='aarch64' \
$PYTHON_BINARY setup.py --ninja \
  build -t /tmp bdist_wheel --skip-build \
  --plat-name "manylinux2014-aarch64"

chown -R 1000:1000 /work/dist
chown -R 1000:1000 /work/build
