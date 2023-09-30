#!/usr/bin/sh
set -ex

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libgcc'
export LDFLAGS='-Wl,--gc-sections -Wl,--strip-all'

export LIEF_BUILD_DIR="/tmp/lief-build"

$PYTHON_BINARY -m pip install tomli pip wheel

pushd /src/api/python
export PYLIEF_CONF=/src/scripts/docker/pylinux-x64.toml \

$PYTHON_BINARY -m pip -vvv wheel --no-build-isolation --wheel-dir=/src/wheel_stage .
$PYTHON_BINARY -m pip -vvv install --user .
popd

find /src/wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w /src/dist {} \;

chown -R 1000:1000 /src/dist /src/wheel_stage
