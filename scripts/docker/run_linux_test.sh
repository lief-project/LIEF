#!/usr/bin/sh
set -ex
export LIEF_SAMPLES_DIR=/tmp/samples
export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libgcc'
export LDFLAGS='-Wl,--gc-sections'

export LIEF_BUILD_DIR="/tmp/lief-build"

$PYTHON_BINARY -m pip install -r /src/tests/requirements.txt
$PYTHON_BINARY -m pip install tomli pip wheel

mkdir -p ${LIEF_SAMPLES_DIR}

$PYTHON_BINARY tests/dl_samples.py ${LIEF_SAMPLES_DIR}

pushd /src/api/python
export PYLIEF_CONF=/src/scripts/docker/pylinux-test-x64.toml

$PYTHON_BINARY -m pip -vvv wheel --no-build-isolation --wheel-dir=/src/wheel_stage .
$PYTHON_BINARY -m pip -vvv install --user .
popd

# Run the Python test suite
$PYTHON_BINARY tests/run_pytest.py
$PYTHON_BINARY tests/run_tools_check.py ${LIEF_BUILD_DIR}/temp

ctest --output-on-failure --test-dir ${LIEF_BUILD_DIR}/temp

# Fuzzing
PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${LIEF_BUILD_DIR}/temp/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_ls.bin -n 100

PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${LIEF_BUILD_DIR}/temp/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_openssl.bin -n 100

PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${LIEF_BUILD_DIR}/temp/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_nm.bin -n 100

find /src/wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w /src/dist {} \;

chown -R 1000:1000 /src/dist /src/wheel_stage
