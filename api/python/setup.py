import os
import platform
import setuptools
import subprocess
import sys
import sysconfig
import tomli
from typing import List, Optional
from pathlib import Path
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from shutil import copy2, which
from tempfile import TemporaryDirectory

CURRENT_DIR     = Path(__file__).parent
LIEF_DIR        = (CURRENT_DIR / ".." / "..").absolute().resolve()
PACKAGE_NAME    = "lief"
PYLIEF_CONF_ENV = "PYLIEF_CONF"
DEFAULT_TARGET  = "pyLIEF"

ENV = os.environ

cmake_conf = None

def report(*args):
    print(*args, file=sys.stderr)

class Config:
    def __init__(self, config: dict):
        self._config = config

        if "cross-compilation" in self._config["lief"]:
            cross_conf = self._config["lief"]["cross-compilation"]
            if "platform" in cross_conf:
                platform_build = cross_conf["platform"]
                if os.name == "nt" and platform_build == "win32":
                    ENV["VSCMD_ARG_TGT_ARCH"] = "x86"
                    os.environ["VSCMD_ARG_TGT_ARCH"] = "x86"


    @classmethod
    def from_file(cls, file: Path):
        with open(file, "rb") as f:
            toml_config = tomli.load(f)
        return cls(toml_config)

    @staticmethod
    def is_windows() -> bool:
        return platform.system() == "Windows" and not sysconfig.get_platform().startswith("mingw")

    def build_type(self) -> str:
        return self._config['lief']['build']['type']

    def build_root_dir(self):
        if env_dir := os.getenv("LIEF_BUILD_DIR"):
            return env_dir
        return self._config['lief']['build'].get('dir', None)

    def get_lief_format_opt(self):
        opt = self._config["lief"]["formats"]
        return (
            "-DLIEF_ELF={}".format("ON" if opt["elf"] else "OFF"),
            "-DLIEF_PE={}".format("ON" if opt["pe"] else "OFF"),
            "-DLIEF_MACHO={}".format("ON" if opt["macho"] else "OFF"),
            "-DLIEF_DEX={}".format("ON" if opt["dex"] else "OFF"),
            "-DLIEF_ART={}".format("ON" if opt["art"] else "OFF"),
            "-DLIEF_OAT={}".format("ON" if opt["oat"] else "OFF"),
            "-DLIEF_VDEX={}".format("ON" if opt["vdex"] else "OFF"),
        )

    def get_lief_logging_opt(self):
        opt = self._config["lief"]["logging"]
        return (
            "-DLIEF_LOGGING={}".format("ON" if opt["enabled"] else "OFF"),
            "-DLIEF_LOGGING_DEBUG={}".format("ON" if opt["debug"] else "OFF"),
        )

    def get_python_opt(self):
        config = ["-DLIEF_PYTHON_API=on"]
        interpreter = Path(sys.executable)
        base = sysconfig.get_config_var("base")
        if base is not None:
            config += [f"-DPython_ROOT_DIR={base}"]

        config += [
            f"-DPython_EXECUTABLE={interpreter.as_posix()}",
        ]
        return config

    def get_generic_opt(self, output: str):
        return (
            f"-DCMAKE_BUILD_TYPE={self.build_type()}",
            f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={output}',
            "-DLIEF_USE_CCACHE={}".format("ON" if self._config["lief"]["build"]["cache"] else "OFF"),
        )

    def get_feat_opt(self):
        opt = self._config["lief"]["features"]
        return (
            "-DLIEF_ENABLE_JSON={}".format("ON" if opt["json"] else "OFF"),
            "-DLIEF_DISABLE_FROZEN={}".format("OFF" if opt["frozen"] else "ON"),
        )

    def get_iwyu_opt(self):
        if "include-what-you-use" in self._config["lief"]["build"]:
            value = self._config["lief"]["build"]["include-what-you-use"]
            return (f"-DCMAKE_CXX_INCLUDE_WHAT_YOU_USE={value}", )
        else:
            return ("-DCMAKE_CXX_INCLUDE_WHAT_YOU_USE=''", )

    def get_flags_opt(self):
        opt = []
        if "cxx-flags" in self._config["lief"]["build"]:
            value = self._config["lief"]["build"]["cxx-flags"]
            opt.append(f"-DCMAKE_CXX_FLAGS={value}")
        else:
            opt.append("-DCMAKE_CXX_FLAGS=''")

        if "c-flags" in self._config["lief"]["build"]:
            value = self._config["lief"]["build"]["c-flags"]
            opt.append(f"-DCMAKE_C_FLAGS={value}")
        else:
            opt.append("-DCMAKE_C_FLAGS=''")

        cxx_flags = os.getenv("CXXFLAGS", None)
        c_flags = os.getenv("CFLAGS", None)

        if cxx_flags is not None:
            opt.append(f'-DCMAKE_CXX_FLAGS={cxx_flags}')

        if c_flags is not None:
            opt.append(f'-DCMAKE_C_FLAGS={c_flags}')

        return opt

    def get_cmake_extra_opt(self):
        opt = []
        if "extra-cmake-opt" in self._config["lief"]["build"]:
            value = self._config["lief"]["build"]["extra-cmake-opt"]
            if isinstance(value, str):
                opt.append(value)
            elif hasattr(value, "__iter__"):
                opt.extend(value)
            else:
                print(f"Unsupported opt: {value} ({type(value)})")
                sys.exit(1)
        return opt


    def get_third_party_opt(self) -> List[str]:
        if "third-party" not in self._config["lief"]:
            return []

        cmake_opt = []
        tp_conf = self._config["lief"]["third-party"]
        if "spdlog" in tp_conf:
            cmake_opt += [
                "-DLIEF_EXTERNAL_SPDLOG=ON",
                "-Dspdlog_DIR={}".format(tp_conf["spdlog"])
            ]
        return cmake_opt

    def get_cross_compile_opt(self) -> List[str]:
        if "cross-compilation" not in self._config["lief"]:
            return []

        cmake_opt = []
        cross_conf = self._config["lief"]["cross-compilation"]
        if "osx-arch" in cross_conf:
            cmake_opt += [
                f'-DCMAKE_OSX_ARCHITECTURES={cross_conf["osx-arch"]}'
            ]
        return cmake_opt

    def get_pre_compile_opt(self):
        install_path = self._config["lief"]["build"].get("lief-install-dir", None)
        if install_path is None:
            return []
        install_path = Path(install_path).expanduser().resolve().absolute()

        if not install_path.is_dir():
            report(f"{install_path} is not a valid directory")
            return []

        cmake_dir = install_path / "share" / "LIEF" / "cmake"
        if not (cmake_dir / "LIEFConfig.cmake").is_file():
            report(f"Missing LIEFConfig.cmake in {cmake_dir}")
            return []

        return (
            "-DLIEF_PY_LIEF_EXT=on",
            "-DLIEF_INSTALL=off",
            f"-DLIEF_DIR={cmake_dir}",
        )

    def gen_cmake_option(self, output: str) -> List[str]:
        cfg = self.build_type()
        opt = [
            *self.get_generic_opt(output),
            *self.get_python_opt(),
            *self.get_lief_format_opt(),
            *self.get_feat_opt(),
            *self.get_iwyu_opt(),
            *self.get_flags_opt(),
            *self.get_third_party_opt(),
            *self.get_pre_compile_opt(),
            *self.get_cross_compile_opt(),
            *self.get_cmake_extra_opt()
        ]

        if self._use_ninja():
            opt = ["-G", "Ninja"] + opt

        if Config.is_windows():
            is64 = sys.maxsize > 2**32
            opt += [
                f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{cfg.upper()}={output}',
                f'-DLIEF_USE_CRT_{cfg.upper()}=MT',
            ]

            if self._use_ninja():
                from setuptools import msvc
                arch = 'x64' if is64 else 'x86'
                report(f"Arch: {arch}")
                ninja_env = msvc.msvc14_get_vc_env(arch)
                ENV.update(ninja_env)
            else:
                opt += ['-A', 'x64'] if is64 else ['-A', 'win32']

        return opt


    def _get_jobs(self) -> List[str]:
        if "parallel-jobs" in self._config["lief"]["build"]:
            jobs = self._config["lief"]["build"]["parallel-jobs"]
            if jobs > 0:
                return ["-j", str(jobs)]
            return []
        return []

    def _get_targets(self) -> List[str]:
        targets = [DEFAULT_TARGET]
        if "extra-targets" in self._config["lief"]["build"]:
            extra = self._config["lief"]["build"]["extra-targets"]
            if isinstance(extra, str):
                targets.append(extra)
            elif hasattr(extra, "__iter__"):
                targets.extend(extra)
            else:
                print(f"Unsupported opt: {targets} ({type(targets)})")
                sys.exit(1)
        return targets

    def get_target_osx_arch(self) -> str:
        if "cross-compilation" in self._config["lief"]:
            cross_conf = self._config["lief"]["cross-compilation"]
            if "osx-arch" in cross_conf:
                arch = cross_conf["osx-arch"]
                return arch
        return platform.machine()

    def _use_ninja(self) -> bool:
        return self._config['lief']['build']['ninja']

    def get_compile_cmd(self):
        config = self._config['lief']['build']['type']
        return [
            'cmake',
            '--build', '.',
            '--target'] + self._get_targets() + [
            '--config', config,
        ] + self._get_jobs()

class Versioning:
    COMMAND         = '{git} describe --tags --long --dirty'
    GIT_BRANCH      = '{git} rev-parse --abbrev-ref HEAD'
    IS_TAGGED_CMD   = '{git} tag --list --points-at=HEAD'
    FMT_DEV         = '{tag}.dev0'
    FMT_TAGGED      = '{tag}'
    DEFAULT_VERSION = "0.14.0"

    def __init__(self):
        self._git = which("git")

    def _exec_git_cmd(self, cmd: str, **kwargs) -> str:
        args = dict(kwargs)
        args["git"] = self._git
        cmd_list = cmd.format(**args).split()
        return subprocess.check_output(cmd_list).decode('utf-8').strip()

    def has_git(self) -> bool:
        return self._git is not None and (LIEF_DIR / ".git").is_dir()

    def get_branch(self) -> Optional[str]:
        if not self.has_git():
            return None

        try:
            return self._exec_git_cmd(Versioning.GIT_BRANCH)
        except subprocess.SubprocessError as e:
            report(f"Error: {e}")
            return None

    def format_version(self, version: str, fmt: str, is_dev: bool = False):
        branch = self.get_branch()
        if branch is not None and branch.startswith("release-"):
            _, version = branch.split("release-")
            return version

        parts = version.split('-')
        assert len(parts) in (3, 4)
        dirty = len(parts) == 4
        tag, count, sha = parts[:3]
        MA, MI, PA = map(int, tag.split(".")) # 0.9.0 -> (0, 9, 0)

        if is_dev:
            tag = f"{MA}.{MI + 1}.{0}"

        if count == '0' and not dirty:
            return tag
        return fmt.format(tag=tag, gitsha=sha.lstrip('g'))

    def version_from_git(self) -> str:
        try:
            is_tagged = self._exec_git_cmd(Versioning.IS_TAGGED_CMD) != ""
            git_version = self._exec_git_cmd(Versioning.COMMAND)
            if is_tagged:
                return self.format_version(version=git_version, fmt=Versioning.FMT_TAGGED)
            return self.format_version(version=git_version, fmt=Versioning.FMT_DEV, is_dev=True)
        except Exception as e:
            report(f"Error: {e}")
            return Versioning.DEFAULT_VERSION


    def get_version(self) -> str:
        if self.has_git():
            return self.version_from_git()

        return Versioning.DEFAULT_VERSION

class LiefDistribution(setuptools.Distribution):
    def __init__(self, attrs=None):
        super().__init__(attrs)

class Module(Extension):
    def __init__(self, name, sourcedir='', *args, **kwargs):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = CURRENT_DIR.resolve().absolute().as_posix()

class BuildLibrary(build_ext):
    def __init__(self, *args, **kwargs):
        self._fix_platform()
        super().__init__(*args, **kwargs)

    def run(self):
        for ext in self.extensions:
            self.build_extension(ext)
        self.copy_extensions_to_source()

    def _fix_platform(self):
        if sys.platform == "darwin":
            deployment_target = os.getenv("MACOSX_DEPLOYMENT_TARGET", None)
            machine = cmake_conf.get_target_osx_arch()
            if deployment_target is None:
                deployment_target = sysconfig.get_config_var("MACOSX_DEPLOYMENT_TARGET")
            os.environ["_PYTHON_HOST_PLATFORM"] = f"macosx-{deployment_target}-{machine}"
            report("Using platform: ", os.environ["_PYTHON_HOST_PLATFORM"])
        else:
            if "cross-compilation" in cmake_conf._config["lief"]:
                cross_conf = cmake_conf._config["lief"]["cross-compilation"]
                if "platform" in cross_conf:
                    platform = cross_conf["platform"]
                    os.environ["_PYTHON_HOST_PLATFORM"] = platform
                    ENV["_PYTHON_HOST_PLATFORM"] = platform
                    report("Using platform: ", platform)
                    if os.name == "nt" and platform == "win32":
                        self.plat_name = "win32"
                        version_fixed = sys.version.lower().replace("amd64", "")
                        sys.version = version_fixed
                        sys.platform = "win32"

    def build_extension(self, ext):
        if build_dir := cmake_conf.build_root_dir():
            self.build_temp = (Path(build_dir) / "tmp").as_posix()
        else:
            self.build_temp = TemporaryDirectory(prefix="lief-tmp-").name


        if build_dir := cmake_conf.build_root_dir():
            self.build_lib = (Path(build_dir) / "base").as_posix()
        else:
            self.build_lib = TemporaryDirectory(prefix="lief-base-").name

        build_temp   = Path(self.build_temp)
        build_lib    = Path(self.build_lib)

        cmake_output = build_temp.parent.absolute()
        cmake_bin = which("cmake")

        if cmake_bin is None:
            raise RuntimeError("Can't find cmake")

        build_temp.mkdir(exist_ok=True, parents=True)
        build_lib.mkdir(exist_ok=True, parents=True)

        report(f"build-temp: {build_temp}")
        report(f"build-lib:  {build_lib}")

        report(f"Platform     : {platform.system()}")
        report(f"Wheel library: {self.get_ext_fullname(ext.name)}")

        cmake_subprocess_args = {
            'cwd': build_temp.as_posix(),
            'env': ENV,
        }

        # 1. Configure
        configure_cmd = [cmake_bin, "-S", LIEF_DIR.as_posix()] + cmake_conf.gen_cmake_option(cmake_output)
        report("CMake Config:", " ".join(configure_cmd))
        subprocess.check_call(configure_cmd, **cmake_subprocess_args)

        compile_cmd = cmake_conf.get_compile_cmd()
        report("Compile with:", " ".join(compile_cmd))
        subprocess.check_call(compile_cmd, **cmake_subprocess_args)

        pylief_dst  = build_lib / self.get_ext_filename(self.get_ext_fullname(ext.name))
        libsuffix = pylief_dst.suffix

        pylief_path = cmake_output / f"{PACKAGE_NAME}{libsuffix}"
        if Config.is_windows():
            pylief_base = cmake_output / "Release" / "api" / "python"
            pylief_path = pylief_base / cmake_conf.build_type() / f"{PACKAGE_NAME}{libsuffix}"
            if not pylief_path.is_file():
                pylief_path = pylief_base / f"{PACKAGE_NAME}{libsuffix}"

            pylief_path = pylief_path.as_posix()

        dst = Path(pylief_dst)
        dst.parent.mkdir(exist_ok=True)

        report(f"Copying {pylief_path} into {pylief_dst}")
        if not self.dry_run:
            copy2(pylief_path, pylief_dst)


versioning = Versioning()
version = versioning.get_version()
report(f"Version is: {version}")

conf_env = os.getenv(PYLIEF_CONF_ENV, None)
conf_file = CURRENT_DIR / "config-default.toml" if conf_env is None else Path(conf_env).absolute().resolve()

cmake_conf = Config.from_file(conf_file)

cmdclass = {
    'build_ext': BuildLibrary,
}

long_description = LIEF_DIR / "package" / "README.rst"

setup(
    long_description=long_description.read_text(),
    long_description_content_type="text/x-rst; charset=UTF-8",
    distclass=LiefDistribution,
    scripts=['examples/elf_reader.py', 'examples/pe_reader.py', 'examples/macho_reader.py'],
    packages=["lief"],
    package_data={"lief": ["py.typed", "*.pyi"]},
    ext_modules=[Module("lief._lief")],
    cmdclass=cmdclass,
    version=version
)
