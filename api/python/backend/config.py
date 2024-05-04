from __future__ import annotations
from pydantic_core import ErrorDetails, core_schema, CoreSchema
from pydantic import BaseModel, ValidationError, Field, GetCoreSchemaHandler
from typing import Any, Optional, Union, List
from pathlib import Path
import tomli
import os
import platform

from typing_extensions import Annotated

from scikit_build_core.settings.skbuild_read_settings import rich_print

def cmake_serialize(field: Any):
    if isinstance(field, bool):
        return "ON" if field else "OFF"
    return field

class EnvStringValidator:
    def _get_env_string(self, string: str) -> str:
        formatted = string.format(
                python_version=os.getenv("LIEF_TARGET_PYTHON_VERSION", ""),
                python_version_alt=os.getenv("LIEF_TARGET_PYTHON_VERSION", "").replace('.', ''),
                architecture=os.getenv("LIEF_TARGET_ARCHITECTURE", ""),
        )
        return formatted

    def __get_pydantic_core_schema__(
        self, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_after_validator_function(
            self._get_env_string, handler(source_type)
        )

EnvString = Annotated[str, EnvStringValidator()]

class BuildConfig(BaseModel):
    build_type: EnvString = Field("Release", alias="type")
    cache: bool = True
    ninja: bool = False
    default_target: str = Field("pyLIEF", alias="default-target")
    parallel_jobs: int = Field(0, alias="parallel-jobs")
    build_dir: Optional[EnvString] = Field(None, alias="build-dir")
    extra_targets: Union[List[EnvString], EnvString] = Field(None, alias="extra-targets")
    extra_cmake: Union[List[EnvString], EnvString] = Field(None, alias="extra-cmake-opt")
    lief_install_dir: Optional[EnvString] = Field(None, alias="lief-install-dir")
    py_api: EnvString = Field("", alias="py-api")
    c_compiler: Optional[EnvString] = Field(None, alias="c-compiler")
    cxx_compiler: Optional[EnvString] = Field(None, alias="cxx-compiler")

    @property
    def targets(self) -> List[str]:
        default_targets: List[str] = [self.default_target]
        if self.extra_targets is not None:
            if isinstance(self.extra_targets, str):
                default_targets.append(self.extra_targets)
            else:
                default_targets.extend(self.extra_targets)

        return default_targets

    def cmake_dump(self) -> List[str]:
        out: List[str] = [
            f"-DLIEF_USE_CCACHE={cmake_serialize(self.cache)}"
        ]

        if self.extra_cmake is not None:
            if isinstance(self.extra_cmake, str):
                out.append(self.extra_cmake)
            elif isinstance(self.extra_cmake, list):
                out.extend(self.extra_cmake)

        if self.lief_install_dir is not None:
            lief_cmake_dir = Path(self.lief_install_dir) / "lib" / "cmake" / "LIEF"
            lief_dir = lief_cmake_dir.expanduser().resolve().absolute()
            out.extend((
                "-DLIEF_PY_LIEF_EXT=on",
                "-DLIEF_INSTALL=off",
                f"-DLIEF_DIR={lief_dir.as_posix()}"
            ))

        if self.c_compiler is not None:
            out.append(
                f"-DCMAKE_C_COMPILER={self.c_compiler}"
            )

        if self.cxx_compiler is not None:
            out.append(
                f"-DCMAKE_CXX_COMPILER={self.cxx_compiler}"
            )

        return out

class ThridParty(BaseModel):
    spdlog: Optional[EnvString] = None

    def cmake_dump(self) -> List[str]:
        out: List[str] = []
        if self.spdlog is not None:
            out.extend((
                "-DLIEF_EXTERNAL_SPDLOG=ON",
                f"-Dspdlog_DIR={self.spdlog}"
            ))

        return out

class CrossCompilation(BaseModel):
    osx_arch: Optional[EnvString]  = Field(None, alias="osx-arch")
    platform: Optional[EnvString] = None
    pyversion: Optional[EnvString] = None
    abi: Optional[EnvString] = None

    def cmake_dump(self) -> List[str]:
        out: List[str] = []
        if self.osx_arch is not None:
            out.extend((
                f'-DCMAKE_OSX_ARCHITECTURES={self.osx_arch}',
            ))
        return out

class Formats(BaseModel):
    elf: bool = True
    pe: bool = True
    macho: bool = True
    dex: bool = True
    art: bool = True
    oat: bool = True
    vdex: bool = True

    def cmake_dump(self) -> List[str]:
        return [
            f"-DLIEF_ELF={cmake_serialize(self.elf)}",
            f"-DLIEF_PE={cmake_serialize(self.pe)}",
            f"-DLIEF_MACHO={cmake_serialize(self.macho)}",
            f"-DLIEF_DEX={cmake_serialize(self.dex)}",
            f"-DLIEF_OAT={cmake_serialize(self.oat)}",
            f"-DLIEF_ART={cmake_serialize(self.art)}",
            f"-DLIEF_VDEX={cmake_serialize(self.vdex)}",
        ]

class Logging(BaseModel):
    enabled: bool = True
    debug: bool = False

    def cmake_dump(self) -> List[str]:
        return [
            f"-DLIEF_LOGGING={cmake_serialize(self.enabled)}",
            f"-DLIEF_LOGGING_DEBUG={cmake_serialize(self.debug)}",
        ]

class Features(BaseModel):
    # json is an attribute already defined in BaseModel
    json_support: bool = Field(True, alias="json")
    frozen: bool = True

    def cmake_dump(self) -> List[str]:
        return [
            f"-DLIEF_ENABLE_JSON={cmake_serialize(self.json_support)}",
            f"-DLIEF_DISABLE_FROZEN={cmake_serialize(not self.frozen)}",
        ]

class ConfigT(BaseModel):
    build: BuildConfig = BuildConfig()
    formats: Formats = Formats()
    third_party: ThridParty = Field(ThridParty(), alias="third-party")
    features: Features = Features()
    logging: Logging = Logging()
    cross_compilation: CrossCompilation = Field(CrossCompilation(),
                                                alias="cross-compilation")

    def _cmake_base_args(self) -> List[str]:
        return [
            "-DLIEF_PYTHON_API=on",
            "-DLIEF_INSTALL=off",
            "-DLIEF_INSTALL_COMPILED_EXAMPLES=off",
        ]

    def cmake_dump(self) -> List[str]:
        return [
            *self._cmake_base_args(),
            *self.build.cmake_dump(),
            *self.formats.cmake_dump(),
            *self.third_party.cmake_dump(),
            *self.features.cmake_dump(),
            *self.logging.cmake_dump(),
            *self.cross_compilation.cmake_dump(),
        ]

def pretty_error(err: ErrorDetails, file: Path):
    loc = '.'.join(err['loc'])
    if err['type'] == 'value_error.missing':
        rich_print(f"[red]'{loc}' is missing in {file}")
    else:
        rich_print(f"[red]Error with '{loc}' in {file} ({err['msg']})")

class Config:
    DEFAULT_EXCLUDE: List[str] = [
        "*.so", "*.pyd"
    ]
    def __init__(self, config: ConfigT):
        self._config: ConfigT = config

    @classmethod
    def from_file(cls, file: Path):
        with open(file, "rb") as f:
            toml_config = tomli.load(f)

        try:
            return cls(ConfigT.model_validate(toml_config["lief"]))
        except ValidationError as e:
            for err in e.errors():
                pretty_error(err, file)
        return None

    @property
    def strip(self) -> str:
        return str(self._config.build.build_type.lower() == "release")

    @property
    def build_dir(self) -> str:
        if bdir := os.getenv("LIEF_BUILD_DIR", None):
            return bdir

        if bdir := self._config.build.build_dir:
            return bdir

        return ""

    def get_cmake_args(self, editable: bool = False) -> List[str]:
        cmake_args = self._config.cmake_dump()
        if editable:
            cmake_args.append(
                "-DLIEF_PYTHON_EDITABLE=ON",
            )
        return cmake_args

    @property
    def cmake_generator(self) -> List[str]:
        if self._config.build.ninja:
            return ["-GNinja",]
        return []

    @property
    def osx_arch(self) -> str:
        return self.cross_compilation.osx_arch or platform.machine()

    def __getattr__(self, name):
        if value := getattr(self._config, name, None):
            return value
        return self.__getattribute__(name)
