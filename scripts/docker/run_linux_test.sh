#!/usr/bin/sh
set -ex
export LIEF_SAMPLES_DIR=/tmp/samples
export CXXFLAGS='-ffunction-sections -fdata-sections -fvisibility-inlines-hidden -static-libgcc'
export CFLAGS='-ffunction-sections -fdata-sections -static-libgcc'
export LDFLAGS='-Wl,--gc-sections'

BUILD_DIR=/tmp/lief-build

$PYTHON_BINARY -m pip install -r /src/tests/requirements.txt

mkdir -p ${LIEF_SAMPLES_DIR}

$PYTHON_BINARY tests/dl_samples.py ${LIEF_SAMPLES_DIR}

pushd /src/api/python
PYLIEF_CONF=/src/scripts/docker/pylinux-test-x64.toml \
$PYTHON_BINARY ./setup.py build --build-base=${BUILD_DIR}/base \
                                --build-temp=${BUILD_DIR}/temp \
                          install --user                       \
                          bdist_wheel --bdist-dir=${BUILD_DIR}/bdist \
                                      --dist-dir=/src/wheel_stage

popd

# Run the Python test suite
$PYTHON_BINARY tests/run_pytest.py
$PYTHON_BINARY tests/run_tools_check.py ${BUILD_DIR}/temp

ctest --output-on-failure --test-dir ${BUILD_DIR}/temp

# Fuzzing
PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${BUILD_DIR}/temp/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_ls.bin -n 100

PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${BUILD_DIR}/temp/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_openssl.bin -n 100

PYTHONPATH=tests/ $PYTHON_BINARY tests/elf/fuzzing.py                                    \
                  ${BUILD_DIR}/temp/tests/Melkor/src/MELKOR/melkor                            \
                  --input-seed ${LIEF_SAMPLES_DIR}/ELF/ELF64_x86-64_binary_nm.bin -n 100

find /src/wheel_stage -iname "*-cp${PYTHON_VERSION}-*" -exec auditwheel repair -w /src/dist {} \;

chown -R 1000:1000 /src/dist /src/wheel_stage
