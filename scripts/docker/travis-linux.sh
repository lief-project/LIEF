#!/usr/bin/sh
set -ex

export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libstdc++ -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libstdc++ -static-libgcc'
export LDFLAGS='-Wl,--gc-sections -Wl,--exclude-libs,ALL'

$PYTHON_BINARY setup.py --ninja --lief-test build \
  bdist_wheel --skip-build --dist-dir wheel_stage

auditwheel repair -w dist --plat manylinux1_x86_64 wheel_stage/*.whl

chown -R 1000:1000 build dist wheel_stage
