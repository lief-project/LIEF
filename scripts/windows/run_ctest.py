import os
import pathlib
import sys
from subprocess import check_call


def _get_vc_env(vc_arch: str) -> dict[str, str]:
    try:
        from setuptools import distutils  # type: ignore

        return distutils._msvccompiler._get_vc_env(vc_arch)
    except AttributeError:
        from setuptools._distutils import (
            _msvccompiler,
        )

        return _msvccompiler._get_vc_env(vc_arch)  # type: ignore


build_dir = pathlib.Path(sys.argv[1]).resolve().absolute().as_posix()

env = os.environ

CWD = pathlib.Path(__file__).parent
LIEF_SRC = (CWD / ".." / "..").resolve().absolute()

is64 = sys.maxsize > 2**32
arch = "x64" if is64 else "x86"

env.update(_get_vc_env(arch))

check_call(
    ["cmake", "-S", LIEF_SRC.as_posix(), "-B", build_dir, "-DLIEF_TESTS=on"], env=env
)

check_call(
    ["cmake", "--build", build_dir, "--target", "all", "--config", "Release"], env=env
)
check_call(["ctest", "--output-on-failure", "--test-dir", build_dir], env=env)
