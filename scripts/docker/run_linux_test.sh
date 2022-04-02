#!/usr/bin/sh
set -ex
export LIEF_SAMPLES_DIR=/tmp/samples
export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libstdc++ -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libstdc++ -static-libgcc'
export LDFLAGS='-Wl,--gc-sections'

$PYTHON_BINARY -m pip install pytest requests

mkdir -p ${LIEF_SAMPLES_DIR}

$PYTHON_BINARY tests/dl_samples.py ${LIEF_SAMPLES_DIR}

$PYTHON_BINARY setup.py --ninja --lief-test build \
  bdist_wheel --skip-build --dist-dir wheel_stage

find wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w dist --plat manylinux2014_x86_64 {} \;

chown -R 1000:1000 build dist wheel_stage
