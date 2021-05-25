#!/usr/bin/sh

# Script to run with liefproject/manylinux2014-x86-64. Example with Python 3.9:
# ==============================================================================================
# docker run \
#  -e CCACHE_DIR=/ccache \
#  -e PYTHON_VERSION=39 \
#  -e PYTHON_BINARY=/usr/local/bin/python3.9 \
#  -v $LIEF_SRC:/work \
#  -v $HOME/.ccache:/ccache \
#  --rm liefproject/manylinux2014-aarch64 bash /work/scripts/docker/manylinux2014-aarch64.sh
# ==============================================================================================

set -ex

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libstdc++ -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libstdc++ -static-libgcc'
export LDFLAGS='-Wl,--gc-sections'

$PYTHON_BINARY setup.py --ninja --lief-test build \
  bdist_wheel --skip-build --dist-dir wheel_stage

find wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w dist {} \;

chown -R 1000:1000 build dist wheel_stage
