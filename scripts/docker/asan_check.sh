#!/usr/bin/sh
set -ex

BUILD_DIR=/tmp/build_asan
SRC_DIR=/src
LOG_DIR=/tmp/sanitize_log
ASAN_OPT="log_path=${LOG_DIR}"
mkdir -p ${LOG_DIR}

cmake -B ${BUILD_DIR} -S ${SRC_DIR} -GNinja \
      -DLIEF_ASAN=ON -DLIEF_LOGGING=on -DLIEF_LOGGING_DEBUG=on \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_COMPILER=/usr/bin/clang++-13 -DCMAKE_C_COMPILER=/usr/bin/clang-13

ninja -C ${BUILD_DIR} sanitize_checks
cd ${BUILD_DIR}

curl -LO https://github.com/lief-project/samples/raw/master/ELF/ELF64_x86-64_binary_all.bin
curl -LO https://github.com/lief-project/samples/raw/master/PE/PE64_x86-64_binary_mfc-application.exe
curl -LO https://github.com/lief-project/samples/raw/master/MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho

${BUILD_DIR}/tests/sanitizer/sanitize_checks ELF64_x86-64_binary_all.bin
${BUILD_DIR}/tests/sanitizer/sanitize_checks PE64_x86-64_binary_mfc-application.exe
${BUILD_DIR}/tests/sanitizer/sanitize_checks 9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho
