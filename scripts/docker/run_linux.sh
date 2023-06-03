#!/usr/bin/sh
set -ex

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libgcc'
export LDFLAGS='-Wl,--gc-sections -Wl,--strip-all'

$PYTHON_BINARY -m pip -vv wheel --wheel-dir=wheel_stage api/python

find wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w dist {} \;

chown -R 1000:1000 api/python/build dist wheel_stage || true
