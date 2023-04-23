#!/usr/bin/bash

# Script to run with liefproject/manylinux2014-aarch64. Example with Python 3.9:
# ==============================================================================================
# docker run \
#  -e CCACHE_DIR=/ccache \
#  -e PYTHON_VERSION=39 \
#  -e PYTHON_BINARY=/opt/python/cp39-cp39/bin/python3.9 \
#  -v $LIEF_SRC:/work \
#  -v $HOME/.ccache:/ccache \
#  --rm liefproject/manylinux2014-aarch64 bash /work/scripts/docker/manylinux2014-aarch64.sh
# ==============================================================================================

set -ex

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libstdc++ -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libstdc++ -static-libgcc'
export LDFLAGS='-Wl,--gc-sections'
export _PYTHON_HOST_PLATFORM="manylinux2014-aarch64"
export SETUPTOOLS_EXT_SUFFIX=$($PYTHON_BINARY -c "import sysconfig;print(sysconfig.get_config_var('EXT_SUFFIX').replace('x86_64', 'aarch64'))")

git config --global --add safe.directory /work

$PYTHON_BINARY -m pip -vv wheel --wheel-dir=dist/ api/python

chown -R 1000:1000 /work/dist /work/api/python/build || true
