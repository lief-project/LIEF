from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Annotated, Any, Literal

import tomli
from pydantic import BaseModel, Field, GetCoreSchemaHandler, ValidationError
from pydantic_core import CoreSchema, ErrorDetails, core_schema
from scikit_build_core._logging import rich_print


def cmake_serialize(field: Any):
    if isinstance(field, bool):
        return "ON" if field else "OFF"
    return field


class EnvStringValidator:
    def _get_env_string(self, string: str) -> str:
        winpy_architecture = os.getenv("LIEF_TARGET_ARCHITECTURE", "")
        if winpy_architecture == "x86_64":
            winpy_architecture = "amd64"
        formatted = string.format(
            python_version=os.getenv("LIEF_TARGET_PYTHON_VERSION", ""),
            python_version_alt=os.getenv("LIEF_TARGET_PYTHON_VERSION", "").replace(
                ".", ""
            ),
            architecture=os.getenv("LIEF_TARGET_ARCHITECTURE", ""),
            winpy_architecture=winpy_architecture,
            ci_project_dir=os.getenv("CI_PROJECT_DIR", ""),
            stable_abi=os.getenv("LIEF_STABLE_ABI", ""),
            free_threaded=os.getenv("LIEF_FREE_THREADED", ""),
            runtime=os.getenv("LIEF_RUNTIME", "false"),
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
    stable_abi: bool | EnvString = Field(False, alias="stable-abi")
    free_threaded: bool | EnvString = Field(False, alias="free-threaded")
    default_target: str = Field("pyLIEF", alias="default-target")
    parallel_jobs: int = Field(0, alias="parallel-jobs")
    compilation_flags: list[str] = Field([], alias="compilation-flags")
    lief_extra_compilation_flags: list[str] = Field(
        [], alias="lief-extra-compilation-flags"
    )
    build_dir: EnvString | None = Field(None, alias="build-dir")
    extra_targets: list[EnvString] | EnvString = Field([], alias="extra-targets")
    extra_cmake: list[EnvString] | EnvString = Field([], alias="extra-cmake-opt")
    lief_install_dir: EnvString | None = Field(None, alias="lief-install-dir")
    py_api: EnvString = Field("", alias="py-api")
    c_compiler: EnvString | None = Field(None, alias="c-compiler")
    cxx_compiler: EnvString | None = Field(None, alias="cxx-compiler")

    @property
    def targets(self) -> list[str]:
        default_targets: list[str] = [self.default_target]
        if self.extra_targets is not None:
            if isinstance(self.extra_targets, str):
                default_targets.append(self.extra_targets)
            else:
                default_targets.extend(self.extra_targets)

        return default_targets

    def cmake_dump(self) -> list[str]:
        out: list[str] = [f"-DLIEF_USE_CCACHE={cmake_serialize(self.cache)}"]

        if self.extra_cmake is not None:
            if isinstance(self.extra_cmake, str):
                out.append(self.extra_cmake)
            elif isinstance(self.extra_cmake, list):
                out.extend(self.extra_cmake)

        if self.lief_install_dir is not None:
            lief_cmake_dir = Path(self.lief_install_dir) / "lib" / "cmake" / "LIEF"
            lief_dir = lief_cmake_dir.expanduser().resolve().absolute()
            out.extend(
                (
                    "-DLIEF_PY_LIEF_EXT=on",
                    "-DLIEF_INSTALL=off",
                    f"-DLIEF_DIR={lief_dir.as_posix()}",
                )
            )

        if self.c_compiler is not None:
            out.append(f"-DCMAKE_C_COMPILER={self.c_compiler}")

        if self.cxx_compiler is not None:
            out.append(f"-DCMAKE_CXX_COMPILER={self.cxx_compiler}")

        if len(self.compilation_flags) > 0:
            flags = " ".join(self.compilation_flags)
            out.extend(
                (
                    f"-DCMAKE_CXX_FLAGS={flags}",
                    f"-DCMAKE_C_FLAGS={flags}",
                )
            )

        if len(self.lief_extra_compilation_flags) > 0:
            flags = ";".join(self.lief_extra_compilation_flags)
            out.extend((f"-DLIEF_EXTRA_FLAGS={flags}",))

        out.extend(
            [
                f"-DLIEF_PYTHON_STABLE_ABI={cmake_serialize(self.stable_abi)}",
                f"-DLIEF_PYTHON_FREE_THREADED={cmake_serialize(self.free_threaded)}",
            ]
        )

        return out


class ThirdParty(BaseModel):
    spdlog: EnvString | None = None
    nanobind: EnvString | None = None

    def cmake_dump(self) -> list[str]:
        out: list[str] = []
        if self.spdlog is not None:
            out.extend(("-DLIEF_EXTERNAL_SPDLOG=ON", f"-Dspdlog_DIR={self.spdlog}"))

        if self.nanobind is not None:
            out.extend(
                ("-DLIEF_OPT_NANOBIND_EXTERNAL=ON", f"-Dnanobind_DIR={self.nanobind}")
            )

        return out


class CrossCompilation(BaseModel):
    osx_arch: EnvString | None = Field(None, alias="osx-arch")
    platform: EnvString | None = None
    pyversion: EnvString | None = None
    abi: EnvString | None = None

    def cmake_dump(self) -> list[str]:
        out: list[str] = []
        if self.osx_arch is not None:
            out.extend((f"-DCMAKE_OSX_ARCHITECTURES={self.osx_arch}",))
        return out


class Formats(BaseModel):
    elf: bool = True
    pe: bool = True
    macho: bool = True
    coff: bool = True
    dex: bool = True
    art: bool = True
    oat: bool = True
    vdex: bool = True

    def cmake_dump(self) -> list[str]:
        return [
            f"-DLIEF_ELF={cmake_serialize(self.elf)}",
            f"-DLIEF_PE={cmake_serialize(self.pe)}",
            f"-DLIEF_MACHO={cmake_serialize(self.macho)}",
            f"-DLIEF_COFF={cmake_serialize(self.coff)}",
            f"-DLIEF_DEX={cmake_serialize(self.dex)}",
            f"-DLIEF_OAT={cmake_serialize(self.oat)}",
            f"-DLIEF_ART={cmake_serialize(self.art)}",
            f"-DLIEF_VDEX={cmake_serialize(self.vdex)}",
        ]


class Logging(BaseModel):
    enabled: bool = True
    debug: bool = False

    def cmake_dump(self) -> list[str]:
        return [
            f"-DLIEF_LOGGING={cmake_serialize(self.enabled)}",
            f"-DLIEF_LOGGING_DEBUG={cmake_serialize(self.debug)}",
        ]


class Features(BaseModel):
    # json is an attribute already defined in BaseModel
    json_support: bool = Field(True, alias="json")
    frozen: bool = True
    runtime: bool | EnvString = Field(False)

    def cmake_dump(self) -> list[str]:
        return [
            f"-DLIEF_RUNTIME={cmake_serialize(self.runtime)}",
            f"-DLIEF_ENABLE_JSON={cmake_serialize(self.json_support)}",
            f"-DLIEF_DISABLE_FROZEN={cmake_serialize(not self.frozen)}",
        ]


class Runtime(BaseModel):
    platform: Literal["linux", "windows", "android", "osx", "ios"] | None = None
    architecture: EnvString | Literal["arm64", "x86_64"] | None = None

    def cmake_dump(self) -> list[str]:
        out: list[str] = []

        if self.platform is not None:
            out.append(f"-DLIEF_RUNTIME_PLATFORM={self.platform}")

        if self.architecture is not None:
            out.append(f"-DLIEF_RUNTIME_ARCH={self.architecture}")

        return out


class ConfigT(BaseModel):
    build: BuildConfig = BuildConfig()
    formats: Formats = Formats()
    third_party: ThirdParty = Field(ThirdParty(), alias="third-party")
    features: Features = Features()
    logging: Logging = Logging()
    runtime: Runtime = Runtime()
    cross_compilation: CrossCompilation = Field(
        CrossCompilation(), alias="cross-compilation"
    )

    def _cmake_base_args(self) -> list[str]:
        return [
            "-DLIEF_PYTHON_API=on",
            "-DLIEF_INSTALL=off",
            "-DLIEF_INSTALL_COMPILED_EXAMPLES=off",
        ]

    def cmake_dump(self) -> list[str]:
        return [
            *self._cmake_base_args(),
            *self.build.cmake_dump(),
            *self.formats.cmake_dump(),
            *self.third_party.cmake_dump(),
            *self.features.cmake_dump(),
            *self.logging.cmake_dump(),
            *self.runtime.cmake_dump(),
            *self.cross_compilation.cmake_dump(),
        ]


def pretty_error(err: ErrorDetails, file: Path):
    loc = ".".join([str(e) for e in err["loc"]])
    if err["type"] == "value_error.missing":
        rich_print(f"[red]'{loc}' is missing in {file}")
    else:
        rich_print(f"[red]Error with '{loc}' in {file} ({err['msg']})")


class Config:
    DEFAULT_EXCLUDE: list[str] = ["*.so", "*.pyd"]

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

    def get_cmake_args(self, editable: bool = False) -> list[str]:
        cmake_args = self._config.cmake_dump()
        if editable:
            cmake_args.append(
                "-DLIEF_PYTHON_EDITABLE=ON",
            )
        return cmake_args

    @property
    def cmake_generator(self) -> list[str]:
        if self._config.build.ninja:
            return [
                "-GNinja",
            ]
        return []

    @property
    def osx_arch(self) -> str:
        return self.cross_compilation.osx_arch or platform.machine()

    def __getattr__(self, name):
        if value := getattr(self._config, name, None):
            return value
        return self.__getattribute__(name)
