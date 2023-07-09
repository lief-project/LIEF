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

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libgcc'
export LDFLAGS='-Wl,--gc-sections'
export _PYTHON_HOST_PLATFORM="manylinux2014-aarch64"
export SETUPTOOLS_EXT_SUFFIX=$($PYTHON_BINARY -c "import sysconfig;print(sysconfig.get_config_var('EXT_SUFFIX').replace('x86_64', 'aarch64'))")

git config --global --add safe.directory /work

BUILD_DIR=/tmp/lief-build
$PYTHON_BINARY -m pip install tomli


pushd /work/api/python
PYLIEF_CONF=/work/scripts/docker/pylinux-aarch64.toml \
$PYTHON_BINARY ./setup.py build --build-base=${BUILD_DIR}/base \
                                --build-temp=${BUILD_DIR}/temp \
                          bdist_wheel --bdist-dir=${BUILD_DIR}/bdist \
                                      --dist-dir=/work/dist
popd
chown -R 1000:1000 /work/dist || true
