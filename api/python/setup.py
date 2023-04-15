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

CURRENT_DIR     = Path(__file__).parent
LIEF_DIR        = (CURRENT_DIR / ".." / "..").absolute().resolve()
PACKAGE_NAME    = "lief"
PYLIEF_CONF_ENV = "PYLIEF_CONF"

ENV = os.environ

cmake_conf = None

def report(*args):
    print(*args)

class Config:
    def __init__(self, config: dict):
        self._config = config

        if "cross-compilation" in self._config["lief"]:
            cross_conf = self._config["lief"]["cross-compilation"]
            if "platform" in cross_conf:
                platform = cross_conf["platform"]
                if os.name == "nt" and platform == "win32":
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

    def gen_cmake_option(self, output: str) -> List[str]:
        cfg = self.build_type()
        opt = [
            f"-DCMAKE_BUILD_TYPE={cfg}",
            f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={output}',
            "-DLIEF_USE_CCACHE={}".format("ON" if self._config["lief"]["build"]["cache"] else "OFF"),
        ] + [
            "-DLIEF_FORCE_API_EXPORTS=ON",
            "-DLIEF_PYTHON_API=on",
            f"-DPYTHON_EXECUTABLE={sys.executable}",
        ] + [
            "-DLIEF_ELF={}".format("ON" if self._config["lief"]["formats"]["elf"] else "OFF"),
            "-DLIEF_PE={}".format("ON" if self._config["lief"]["formats"]["pe"] else "OFF"),
            "-DLIEF_MACHO={}".format("ON" if self._config["lief"]["formats"]["macho"] else "OFF"),
            "-DLIEF_DEX={}".format("ON" if self._config["lief"]["formats"]["dex"] else "OFF"),
            "-DLIEF_ART={}".format("ON" if self._config["lief"]["formats"]["art"] else "OFF"),
            "-DLIEF_OAT={}".format("ON" if self._config["lief"]["formats"]["oat"] else "OFF"),
            "-DLIEF_VDEX={}".format("ON" if self._config["lief"]["formats"]["vdex"] else "OFF"),
        ] + [
            "-DLIEF_LOGGING={}".format("ON" if self._config["lief"]["logging"]["enabled"] else "OFF"),
            "-DLIEF_LOGGING_DEBUG={}".format("ON" if self._config["lief"]["logging"]["debug"] else "OFF"),
        ] + [
            "-DLIEF_ENABLE_JSON={}".format("ON" if self._config["lief"]["features"]["json"] else "OFF"),
            "-DLIEF_DISABLE_FROZEN={}".format("OFF" if self._config["lief"]["features"]["frozen"] else "ON"),
        ] + [
            "-DLIEF_ENABLE_JSON={}".format("ON" if self._config["lief"]["features"]["json"] else "OFF"),
            "-DLIEF_DISABLE_FROZEN={}".format("OFF" if self._config["lief"]["features"]["frozen"] else "ON"),
        ]

        if "include-what-you-use" in self._config["lief"]["build"]:
            value = self._config["lief"]["build"]["include-what-you-use"]
            opt.append(f"-DCMAKE_CXX_INCLUDE_WHAT_YOU_USE={value}")
        else:
            opt.append("-DCMAKE_CXX_INCLUDE_WHAT_YOU_USE=''")

        cxx_flags = os.getenv("CXXFLAGS", None)
        c_flags = os.getenv("CFLAGS", None)

        if cxx_flags is not None:
            opt.append(f'-DCMAKE_CXX_FLAGS={cxx_flags}')

        if c_flags is not None:
            opt.append(f'-DCMAKE_C_FLAGS={c_flags}')

        if self._use_ninja():
            opt = ["-G", "Ninja"] + opt


        opt += self._get_third_party_opt()
        opt += self._get_cross_compile_opt()

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

    def _get_third_party_opt(self) -> List[str]:
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

    def _get_cross_compile_opt(self) -> List[str]:
        if "cross-compilation" not in self._config["lief"]:
            return []

        cmake_opt = []
        cross_conf = self._config["lief"]["cross-compilation"]
        if "osx-arch" in cross_conf:
            cmake_opt += [
                f'-DCMAKE_OSX_ARCHITECTURES={cross_conf["osx-arch"]}'
            ]
        return cmake_opt

    def _get_jobs(self) -> List[str]:
        if "parallel-jobs" in self._config["lief"]["build"]:
            jobs = self._config["lief"]["build"]["parallel-jobs"]
            if jobs > 0:
                return ["-j", str(jobs)]
            return []
        return []

    def get_target_osx_arch(self) -> str:
        if "cross-compilation" in self._config["lief"]:
            cross_conf = self._config["lief"]["cross-compilation"]
            if "osx-arch" in cross_conf:
                arch = cross_conf["osx-arch"]
                return arch
        return platform.machine()

    def _use_ninja(self) -> bool:
        return self._config['lief']['build']['ninja']

    def _win_compile_cmd(self):
        return [
            'cmake',
            '--build', '.',
            '--target', 'pyLIEF',
            '--config', self._config['lief']['build']['type'],
        ]

    def _unix_compile_cmd(self):
        gen  = which("ninja") if self._use_ninja() else which("make")
        return [gen] + self._get_jobs() + ["pyLIEF"]

    def get_compile_cmd(self):
        if Config.is_windows():
            return self._win_compile_cmd()

        return self._unix_compile_cmd()


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
        report(" ".join(configure_cmd))
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
