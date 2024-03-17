from setuptools import msvc
import os
import sys
from subprocess import check_call
import shutil
from pathlib import Path

env = os.environ

for k, v in os.environ.items():
    print(f"   {k}:{v}")

CWD = Path(__file__).parent
LIEF_SRC = CWD / ".." / ".."
RUNNER_TEMP = os.getenv("RUNNER_TEMP", None)
if RUNNER_TEMP is None:
    print("'RUNNER_TEMP' is not set!", file=sys.stderr)
    sys.exit(1)

INSTALL_DIR = Path(RUNNER_TEMP) / "lief-install"

BUILD_PATH = LIEF_SRC / "build"
BUILD_STATIC_PATH = BUILD_PATH / "static-release"
BUILD_SHARED_PATH = BUILD_PATH / "shared-release"
CPACK_CONFIG_PATH = (LIEF_SRC / "cmake" / "cpack.config.cmake").resolve()

CMAKE_PATH = Path(shutil.which("cmake.exe"))
CPACK_PATH = CMAKE_PATH.parent / "cpack.exe"

if not CPACK_PATH.is_file():
    print(f"Can't find cpack.exe at: {CPACK_PATH}", file=sys.stderr)
    sys.exit(1)

CPACK_BIN = CPACK_PATH.as_posix()

BUILD_PATH.mkdir(exist_ok=True)
BUILD_STATIC_PATH.mkdir(exist_ok=True)
BUILD_SHARED_PATH.mkdir(exist_ok=True)

is64 = sys.maxsize > 2**32
arch = 'x64' if is64 else 'x86'

ninja_env = msvc.msvc14_get_vc_env(arch)
env.update(ninja_env)

cmake_config_static = [
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DBUILD_SHARED_LIBS=off",
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded",
    "-DLIEF_PYTHON_API=off",
    "-DLIEF_INSTALL_COMPILED_EXAMPLES=on",
    f"-DCMAKE_INSTALL_PREFIX={INSTALL_DIR.as_posix()}"
]

cmake_config_shared = [
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL",
    "-DBUILD_SHARED_LIBS=on",
    "-DLIEF_PYTHON_API=off",
    "-DLIEF_INSTALL_COMPILED_EXAMPLES=off",
]

build_args = ['--config', 'Release']
configure_cmd = ['cmake', LIEF_SRC.resolve().as_posix()]

print("Building shared version")
check_call(configure_cmd + cmake_config_shared,
           cwd=BUILD_SHARED_PATH.resolve().as_posix(),
           env=env)
check_call(['cmake', '--build', '.', '--target', "all"] + build_args,
           cwd=BUILD_SHARED_PATH.resolve().as_posix(),
           env=env)

print("Building static version")
check_call(configure_cmd + cmake_config_static,
           cwd=BUILD_STATIC_PATH.resolve().as_posix(),
           env=env)

check_call(['cmake', '--build', '.', '--target', "install"] + build_args,
           cwd=BUILD_STATIC_PATH.resolve().as_posix(),
           env=env)

check_call([CPACK_BIN, '--config', CPACK_CONFIG_PATH.resolve().as_posix()],
           cwd=BUILD_PATH.resolve().as_posix(),
           env=env)
