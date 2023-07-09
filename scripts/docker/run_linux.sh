#!/usr/bin/sh
set -ex

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libgcc'
export LDFLAGS='-Wl,--gc-sections -Wl,--strip-all'

BUILD_DIR=/tmp/lief-build

$PYTHON_BINARY -m pip install tomli

pushd /src/api/python
PYLIEF_CONF=/src/scripts/docker/pylinux-x64.toml \
$PYTHON_BINARY ./setup.py build --build-base=${BUILD_DIR}/base \
                                --build-temp=${BUILD_DIR}/temp \
                          bdist_wheel --bdist-dir=${BUILD_DIR}/bdist \
                                      --dist-dir=/src/wheel_stage
popd

find /src/wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w /src/dist {} \;

chown -R 1000:1000 /src/dist /src/wheel_stage
