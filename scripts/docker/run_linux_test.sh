#!/usr/bin/sh
set -ex
export LIEF_SAMPLES_DIR=/tmp/samples
export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libgcc'
export LDFLAGS='-Wl,--gc-sections'

$PYTHON_BINARY -m pip install pytest requests

mkdir -p ${LIEF_SAMPLES_DIR}

$PYTHON_BINARY tests/dl_samples.py ${LIEF_SAMPLES_DIR}

$PYTHON_BINARY -m pip -vv wheel --wheel-dir=wheel_stage api/python
$PYTHON_BINARY -m pip -vv install api/python
# Run the Python test suite
$PYTHON_BINARY tests/run_pytest.py

BUILD_DIR="$(pwd)/api/python/build/temp.linux-x86_64-cpython-${PYTHON_VERSION}/"
cmake . -B ${BUILD_DIR} -DLIEF_TESTS=on
ninja -C ${BUILD_DIR}


$PYTHON_BINARY tests/run_tools_check.py ${BUILD_DIR}

ctest --output-on-failure --test-dir ${BUILD_DIR}

# Fuzzing
PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${BUILD_DIR}/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_ls.bin -n 100

PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${BUILD_DIR}/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_openssl.bin -n 100

PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${BUILD_DIR}/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_nm.bin -n 100

find wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w dist {} \;

chown -R 1000:1000 api/python/build dist wheel_stage
