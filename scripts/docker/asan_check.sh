#!/usr/bin/sh
shopt -s globstar
set -e
BUILD_DIR=/tmp/build_asan
SRC_DIR=/src
LOG_DIR=/tmp/sanitize_log
SAMPLE_DIR=/tmp/samples
ASAN_OPT="log_path=${LOG_DIR}"
mkdir -p ${LOG_DIR}

cmake -B ${BUILD_DIR} -S ${SRC_DIR} -GNinja \
      -DLIEF_ASAN=ON -DLIEF_LOGGING=on -DLIEF_LOGGING_DEBUG=on \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER=/usr/bin/clang++-13 -DCMAKE_C_COMPILER=/usr/bin/clang-13

ninja -C ${BUILD_DIR} sanitize_checks
cd ${BUILD_DIR}


mkdir -p ${SAMPLE_DIR}

pushd ${SAMPLE_DIR}
curl -LO https://data.romainthomas.fr/lief_tests.zip
unzip lief_tests.zip
popd

for x in ${SAMPLE_DIR}/**; do echo $x && ${BUILD_DIR}/tests/sanitizer/sanitize_checks $x; done
