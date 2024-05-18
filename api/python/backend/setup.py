from __future__ import annotations
from pathlib import Path
import os
import sys
import sysconfig
from functools import lru_cache
from typing import Optional, Union, List

CWD = Path(__file__).parent
ROOT_DIR = CWD / ".." / ".." / ".."
BINDING_DIR = ROOT_DIR / "api" / "python"
SRC_DIR = ROOT_DIR.resolve().absolute()

DEFAULT_CONF = CWD / ".." / "config-default.toml"

_WHEEL_TAG_COMPUTE_BEST = None

@lru_cache(maxsize=1)
def get_config():
    from config import Config
    if path := os.getenv("PYLIEF_CONF"):
        config_path = Path(path).resolve().absolute()
        return Config.from_file(config_path)
    return Config.from_file(DEFAULT_CONF.as_posix())


def _compute_best(cls, *arg, **kwargs):
    from scikit_build_core.builder.wheel_tag import WheelTag
    best_tag = _WHEEL_TAG_COMPUTE_BEST(cls, *arg, **kwargs)
    config = get_config()

    pyvers = best_tag.pyvers
    abis = best_tag.abis
    archs = best_tag.archs

    if version := config.cross_compilation.pyversion:
        pyvers = [version]

    if abi := config.cross_compilation.abi:
        abis = [abi]

    if platform := config.cross_compilation.platform:
        archs = [platform]

    return WheelTag(pyvers, abis, archs)

def _fix_env():
    config = get_config()
    if sys.platform.startswith("win"):
        if config.build.ninja:
            from setuptools import msvc
            is64 = sys.maxsize > 2**32
            arch = 'x64' if is64 else 'x86'
            ninja_env = msvc.msvc14_get_vc_env(arch)
            os.environ.update(ninja_env)

    if sys.platform.startswith("darwin"):
        deployment_target = (
                os.getenv("MACOSX_DEPLOYMENT_TARGET", None) or
                sysconfig.get_config_var("MACOSX_DEPLOYMENT_TARGET")
        )
        os.environ["_PYTHON_HOST_PLATFORM"] = f"macosx-{deployment_target}-{config.osx_arch}"
        # scikit_build_core is aware of ARCHFLAGS for the wheel arch:
        # builder/builder.py:get_archs()
        os.environ["ARCHFLAGS"]= f"-arch {config.osx_arch}"

    if platform := config.cross_compilation.platform:
        global _WHEEL_TAG_COMPUTE_BEST
        from scikit_build_core.builder.wheel_tag import WheelTag
        _WHEEL_TAG_COMPUTE_BEST = WheelTag.compute_best
        WheelTag.compute_best = _compute_best

        os.environ["_PYTHON_HOST_PLATFORM"] = platform

        if os.name == 'nt' and platform == 'win32':
            os.environ["VSCMD_ARG_TGT_ARCH"] = "x86"
            sys.version = sys.version.lower().replace("amd64", "")
            sys.platform = "win32"

def _get_hooked_config(is_editable: bool) -> Optional[dict[str, Union[str, List[str]]]]:
    from config import Config

    config = get_config()

    if config is None:
        raise RuntimeError("Can't get the configuration")

    if config.build.py_api.startswith("cp3"):
        # https://github.com/scikit-build/scikit-build-core/blob/9ac2e35aa888b70e9f1999a75dfafb7a5d709f88/src/scikit_build_core/builder/wheel_tag.py#L83-L85
        # Make sure that this check is not silently warned since it could lead
        # to a wrong .whl filename
        minor = int(config.build.py_api[3:])
        if (
            sys.implementation.name != "cpython" or
            minor > sys.version_info.minor
        ):
            msg = f"Ignoring py-api, not a CPython interpreter ({sys.implementation.name}) or version (3.{minor}) is too high"
            raise RuntimeError(msg)


    config_settings = {
        "logging.level": "DEBUG",
        "build-dir": config.build_dir,
        "install.strip": config.strip,
        "backport.find-python": "0",
        "wheel.py-api":  config.build.py_api,
        "cmake.source-dir": SRC_DIR.as_posix(),
        "cmake.build-type": config.build.build_type,
        "cmake.targets": config.build.targets,
        "cmake.args": [
            *config.cmake_generator,
            *config.get_cmake_args(is_editable),
        ],
        "sdist.exclude": Config.DEFAULT_EXCLUDE,
    }
    return config_settings

def _get_build_requirements(is_editable: bool) -> List[str]:
    build_req_file = BINDING_DIR / "build-requirements.txt"
    reqs = [line for line in build_req_file.read_text().splitlines() if not line.startswith("#")]
    return reqs

def get_requires_for_build_wheel(
    config_settings: Optional[dict[str, Union[str, List[str]]]] = None,
) -> list[str]:
    return _get_build_requirements(is_editable=False)

def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: Optional[dict[str, Union[str, List[str]]]] = None,
) -> str:
    from scikit_build_core.build import prepare_metadata_for_build_wheel as _impl
    _fix_env()
    return _impl(metadata_directory, config_settings)

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    from scikit_build_core.build import build_wheel as _impl

    config_settings = _get_hooked_config(is_editable=False)
    _fix_env()
    return _impl(wheel_directory, config_settings, metadata_directory)

def get_requires_for_build_editable(
    config_settings: Optional[dict[str, Union[str, List[str]]]] = None,
) -> List[str]:
    return _get_build_requirements(is_editable=True)

def prepare_metadata_for_build_editable(
    metadata_directory: str,
    config_settings: Optional[dict[str, Union[str, List[str]]]] = None,
) -> str:
    from scikit_build_core.build import prepare_metadata_for_build_editable as _impl
    _fix_env()
    return _impl(metadata_directory, config_settings)

def build_editable(
    wheel_directory: str,
    config_settings: Optional[dict[str, Union[str, List[str]]]] = None,
    metadata_directory: Optional[str] = None,
) -> str:
    from scikit_build_core.build import build_editable as _impl

    config_settings = _get_hooked_config(is_editable=True)
    _fix_env()
    return _impl(wheel_directory, config_settings, metadata_directory)

def build_sdist(
    sdist_directory: str,
    config_settings: Optional[dict[str, Union[str, List[str]]]] = None,
) -> str:
    raise RuntimeError("LIEF does not support Python source distribution ('sdist')")
