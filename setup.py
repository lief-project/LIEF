import os
import sys
import platform
import subprocess
import setuptools
import pathlib
import sysconfig
import copy
import distutils
from pkg_resources import get_distribution
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from distutils import log
from shutil import copy2

try:
    from packaging import version
except ImportError:
    # Fallback on the packaging embedded in setuptools.
    # This is not the cleanest solution but it enables to avoid an extra dependency.
    from setuptools._vendor.packaging import version

MIN_SETUPTOOLS_VERSION = "31.0.0"
assert (version.parse(setuptools.__version__) >= version.parse(MIN_SETUPTOOLS_VERSION)), \
        f"LIEF requires a setuptools version '{MIN_SETUPTOOLS_VERSION}' or higher (pip install setuptools --upgrade)"

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
PACKAGE_NAME = "lief"

get_config_var_backup  = sysconfig.get_config_var
get_platform_backup    = sysconfig.get_platform
get_config_vars_backup = sysconfig.get_config_vars
distutils_get_config_vars_backup = distutils.sysconfig.get_config_vars

class LiefDistribution(setuptools.Distribution):
    global_options = setuptools.Distribution.global_options + [
        ('lief-test', None, 'Build and make tests'),
        ('ninja', None, 'Use Ninja as build system'),
        ('sdk', None, 'Build SDK package'),
        ('doc', None, 'Build LIEF documentation'),

        ('lief-no-json', None, 'Disable JSON module'),
        ('lief-no-logging', None, 'Disable logging module'),

        ('lief-no-elf', None, 'Disable ELF module'),
        ('lief-no-pe', None, 'Disable PE module'),
        ('lief-no-macho', None, 'Disable Mach-O module'),

        ('lief-no-android', None, 'Disable Android formats'),
        ('lief-no-art', None, 'Disable ART module'),
        ('lief-no-vdex', None, 'Disable VDEX module'),
        ('lief-no-oat', None, 'Disable OAT module'),
        ('lief-no-dex', None, 'Disable DEX module'),

        ('lief-no-cache', None, 'Do not use compiler cache (ccache)'),

        ('spdlog-dir=', None, 'Path to the directory that contains spdlogConfig.cmake'),
        ('lief-config-extra=', None, "Extra CMake config options (list delimited with ';')"),
    ]

    def __init__(self, attrs=None):
        self.lief_test    = False
        self.ninja        = False
        self.sdk          = False

        self.lief_no_json    = False
        self.lief_no_logging = False

        self.lief_no_elf    = False
        self.lief_no_pe     = False
        self.lief_no_macho  = False

        self.lief_no_art   = False
        self.lief_no_oat   = False
        self.lief_no_dex   = False
        self.lief_no_vdex  = False

        self.lief_no_android  = False
        self.doc = False

        self.lief_no_cache  = False

        self.spdlog_dir = None
        self.lief_config_extra = None
        super().__init__(attrs)


class Module(Extension):
    def __init__(self, name, sourcedir='', *args, **kwargs):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(os.path.join(CURRENT_DIR))


class BuildLibrary(build_ext):
    def run(self):
        try:
            subprocess.check_output(['cmake', '--version'])
        except OSError:
            raise RuntimeError("CMake must be installed to build the following extensions: " +
                               ", ".join(e.name for e in self.extensions))

        for ext in self.extensions:
            self.build_extension(ext)
        self.copy_extensions_to_source()

    @staticmethod
    def has_ninja():
        try:
            subprocess.check_call(['ninja', '--version'])
            return True
        except Exception:
            return False

    @staticmethod
    def sdk_suffix():
        if platform.system() == "Windows":
            return "zip"
        return "tar.gz"

    def build_extension(self, ext):
        if self.distribution.lief_test:
            log.info("LIEF tests enabled!")
        fullname = self.get_ext_fullname(ext.name)
        jobs = self.parallel if self.parallel else 1
        cmake_args = ["-DLIEF_FORCE_API_EXPORTS=ON", "-DLIEF_PYTHON_API=on"]
        build_temp                     = self.build_temp
        cmake_library_output_directory = os.path.abspath(os.path.dirname(build_temp))
        cfg                            = 'RelWithDebInfo' if self.debug else 'Release'
        is64                           = sys.maxsize > 2**32

        # Ninja ?
        build_with_ninja = False
        if self.has_ninja() and self.distribution.ninja:
            build_with_ninja = True

        if build_with_ninja:
            cmake_args += ["-G", "Ninja"]

        cmake_args += [
            f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={cmake_library_output_directory}',
            f'-DPYTHON_EXECUTABLE={sys.executable}',
            '-DLIEF_PYTHON_API=on',
        ]

        # LIEF options
        # ============
        if self.distribution.lief_test:
            cmake_args += ["-DLIEF_TESTS=on"]

        if self.distribution.lief_no_json:
            log.info("LIEF JSON module disabled")
            cmake_args += ["-DLIEF_ENABLE_JSON=off"]

        if self.distribution.lief_no_logging:
            log.info("LIEF logging module disabled")
            cmake_args += ["-DLIEF_LOGGING=off"]

        if self.distribution.doc:
            log.info("LIEF documentation enabled")
            cmake_args += ["-DLIEF_DOC=on"]

        if self.debug:
            log.info("LIEF enables DEBUG messages")
            cmake_args += ["-DLIEF_LOGGING_DEBUG=on"]
        else:
            cmake_args += ["-DLIEF_LOGGING_DEBUG=off"]

        if self.distribution.lief_no_cache:
            cmake_args += ["-DLIEF_USE_CCACHE=off"]

        # Setup spdlog configuration flags if
        # the user provides --spdlog-dir
        if self.distribution.spdlog_dir is not None:
            cmake_args.append("-DLIEF_EXTERNAL_SPDLOG=ON")
            cmake_args.append(f"-Dspdlog_DIR={self.distribution.spdlog_dir}")

        if self.distribution.lief_config_extra is not None and len(self.distribution.lief_config_extra) > 0:
            args = self.distribution.lief_config_extra.replace("\n", "")
            args = map(lambda a : a.strip(), args.split(";"))
            cmake_args += list(args)

        # Main formats
        # ============
        if self.distribution.lief_no_elf:
            log.info("LIEF ELF module disabled")
            cmake_args += ["-DLIEF_ELF=off"]

        if self.distribution.lief_no_pe:
            log.info("LIEF PE module disabled")
            cmake_args += ["-DLIEF_PE=off"]

        if self.distribution.lief_no_macho:
            log.info("LIEF MACH-O module disabled")
            cmake_args += ["-DLIEF_MACHO=off"]

        # Android formats
        # ===============
        if self.distribution.lief_no_oat or self.distribution.lief_no_android:
            log.info("LIEF OAT module disabled")
            cmake_args += ["-DLIEF_OAT=off"]

        if self.distribution.lief_no_dex or self.distribution.lief_no_android:
            log.info("LIEF DEX module disabled")
            cmake_args += ["-DLIEF_DEX=off"]

        if self.distribution.lief_no_vdex or self.distribution.lief_no_android:
            log.info("LIEF VDEX module disabled")
            cmake_args += ["-DLIEF_VDEX=off"]

        if self.distribution.lief_no_art or self.distribution.lief_no_android:
            log.info("LIEF ART module disabled")
            cmake_args += ["-DLIEF_ART=off"]

        build_args = ['--config', cfg]

        env = os.environ
        cxx_flags = os.getenv("CXXFLAGS", None)
        c_flags = os.getenv("CFLAGS", None)

        if cxx_flags is not None:
            cmake_args += [
                f'-DCMAKE_CXX_FLAGS={cxx_flags}',
            ]

        if c_flags is not None:
            cmake_args += [
                f'-DCMAKE_C_FLAGS={c_flags}',
            ]


        if platform.system() == "Windows" and not sysconfig.get_platform().startswith("mingw"):
            from setuptools import msvc

            cmake_args += [
                f'-DCMAKE_BUILD_TYPE={cfg}',
                f'-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{cfg.upper()}={cmake_library_output_directory}',
                '-DLIEF_USE_CRT_RELEASE=MT',
            ]
            if build_with_ninja:
                arch = 'x64' if is64 else 'x86'
                ninja_env = msvc.msvc14_get_vc_env(arch)
                env.update(ninja_env)
            else:
                cmake_args += ['-A', 'x64'] if is64 else ['-A', 'win32']
                build_args += ['--', '/m']
        else:
            cmake_args += [f'-DCMAKE_BUILD_TYPE={cfg}']


        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)

        log.info(f"Platform: %s", platform.system())
        log.info("Wheel library: %s", self.get_ext_fullname(ext.name))

        # 1. Configure
        configure_cmd = ['cmake', ext.sourcedir] + cmake_args
        log.info(" ".join(configure_cmd))
        subprocess.check_call(configure_cmd, cwd=self.build_temp, env=env)

        # 2. Build
        targets = {
            'python_bindings': 'pyLIEF',
        }
        if self.distribution.sdk:
            targets['sdk'] = "package"

        if self.distribution.doc:
            targets['doc'] = "lief-doc"

        if platform.system() == "Windows" and not sysconfig.get_platform().startswith("mingw"):
            if self.distribution.lief_test:
                subprocess.check_call(configure_cmd, cwd=self.build_temp, env=env)
                if build_with_ninja:
                    subprocess.check_call(['cmake', '--build', '.', '--target', "all"] + build_args, cwd=self.build_temp, env=env)
                else:
                    subprocess.check_call(['cmake', '--build', '.', '--target', "ALL_BUILD"] + build_args, cwd=self.build_temp, env=env)
                subprocess.check_call(['cmake', '--build', '.', '--target', "check-lief"] + build_args, cwd=self.build_temp, env=env)
            else:
                subprocess.check_call(['cmake', '--build', '.', '--target', targets['python_bindings']] + build_args, cwd=self.build_temp, env=env)

            if 'sdk' in targets:
                subprocess.check_call(['cmake', '--build', '.', '--target', targets['sdk']] + build_args, cwd=self.build_temp, env=env)

        else:
            if self.parallel:
                log.info(f"Using {jobs} jobs")

            if build_with_ninja:
                jobs_opt = ["-j", str(jobs)] if self.parallel else []
                if self.distribution.lief_test:
                    subprocess.check_call(configure_cmd, cwd=self.build_temp)
                    subprocess.check_call(['ninja'] + jobs_opt, cwd=self.build_temp)
                    subprocess.check_call(['ninja'] + jobs_opt + ["check-lief"], cwd=self.build_temp)
                else:
                    subprocess.check_call(['ninja'] + jobs_opt + [targets['python_bindings']], cwd=self.build_temp, env=env)

                if 'sdk' in targets:
                    subprocess.check_call(['ninja'] + jobs_opt + [targets['sdk']], cwd=self.build_temp, env=env)

                if 'doc' in targets:
                    try:
                        subprocess.check_call(['ninja'] + jobs_opt + [targets['doc']], cwd=self.build_temp, env=env)
                    except Exception as e:
                        log.error(f"Documentation failed: {e}")
            else:
                if self.distribution.lief_test:
                    subprocess.check_call(configure_cmd, cwd=self.build_temp)
                    subprocess.check_call(['make', '-j', str(jobs), "all"], cwd=self.build_temp)
                    subprocess.check_call(['make', '-j', str(jobs), "check-lief"], cwd=self.build_temp)
                else:
                    subprocess.check_call(['make', '-j', str(jobs), targets['python_bindings']], cwd=self.build_temp, env=env)

                if 'sdk' in targets:
                    subprocess.check_call(['make', '-j', str(jobs), targets['sdk']], cwd=self.build_temp, env=env)

                if 'doc' in targets:
                    try:
                        subprocess.check_call(['make', '-j', str(jobs), targets['doc']], cwd=self.build_temp, env=env)
                    except Exception as e:
                        log.error(f"Documentation failed: {e}")
        pylief_dst  = os.path.join(self.build_lib, self.get_ext_filename(self.get_ext_fullname(ext.name)))
        libsuffix = pylief_dst.split(".")[-1]

        pylief_path = os.path.join(cmake_library_output_directory, "{}.{}".format(PACKAGE_NAME, libsuffix))
        if platform.system() == "Windows" and not sysconfig.get_platform().startswith("mingw"):
            pylief_base = pathlib.Path(cmake_library_output_directory) / "Release" / "api" / "python"
            pylief_path = pylief_base / "Release" / "{}.{}".format(PACKAGE_NAME, libsuffix)
            if not pylief_path.is_file():
                pylief_path = pylief_base / "{}.{}".format(PACKAGE_NAME, libsuffix)

            pylief_path = pylief_path.as_posix()

        if not os.path.exists(self.build_lib):
            os.makedirs(self.build_lib)

        log.info(f"Copying {pylief_path} into {pylief_dst}")
        if not self.dry_run:
            copy2(pylief_path, pylief_dst)


        # SDK
        # ===
        if self.distribution.sdk:
            sdk_path = list(pathlib.Path(self.build_temp).rglob(f"LIEF-*.{self.sdk_suffix()}"))
            if len(sdk_path) == 0:
                log.error("Unable to find SDK archive")
                sys.exit(1)

            sdk_path = str(sdk_path.pop())
            sdk_output = str(pathlib.Path(CURRENT_DIR) / "build")
            if not self.dry_run:
                copy2(sdk_path, sdk_output)

def get_platform():
    out = get_platform_backup()
    lief_arch = os.environ.get("LIEF_PY_XARCH", None)
    if lief_arch is not None and isinstance(out, str):
        original_out = out
        out = out.replace("x86_64", lief_arch)
        log.info(f"   Replace {original_out} -> {out}")
    return out

def get_config_vars(*args):
    out = get_config_vars_backup(*args)
    lief_arch = os.environ.get("LIEF_PY_XARCH", None)
    if lief_arch is None:
        return out
    out_xfix = copy.deepcopy(out)
    for k, v in out.items():
        if not (isinstance(v, str) and "x86_64" in v):
            continue
        if k not in {"SO", "SOABI", "EXT_SUFFIX", "BUILD_GNU_TYPE"}:
            continue
        fix = v.replace("x86_64", lief_arch)
        log.info(f"   Replace {k}: {v} -> {fix}")
        out_xfix[k] = fix

    return out_xfix


def distutils_get_config_vars(*args):
    out = distutils_get_config_vars_backup(*args)
    lief_arch = os.environ.get("LIEF_PY_XARCH", None)
    if lief_arch is None:
        return out

    if isinstance(out, list):
        fixes = []
        for item in out:
            if not (isinstance(item, str) and "x86_64" in item):
                fixes.append(item)
            else:
                fixes.append(item.replace("x86_64", lief_arch))
        return fixes

    out_xfix = copy.deepcopy(out)
    for k, v in out.items():
        if not (isinstance(v, str) and "x86_64" in v):
            continue
        if k not in {"SO", "SOABI", "EXT_SUFFIX", "BUILD_GNU_TYPE"}:
            continue
        fix = v.replace("x86_64", lief_arch)
        log.info(f"   Replace {k}: {v} -> {fix}")
        out_xfix[k] = fix

    return out_xfix

sysconfig.get_platform              = get_platform
sysconfig.get_config_vars           = get_config_vars
distutils.sysconfig.get_config_vars = distutils_get_config_vars

# From setuptools-git-version
command       = 'git describe --tags --long --dirty'
git_branch    = 'git rev-parse --abbrev-ref HEAD'
is_tagged_cmd = 'git tag --list --points-at=HEAD'
fmt_dev       = '{tag}.dev0'
fmt_tagged    = '{tag}'

def get_branch():
    try:
        return subprocess.check_output(git_branch.split()).decode('utf-8').strip()
    except Exception:
        return None

def format_version(version: str, fmt: str = fmt_dev, is_dev: bool = False):
    branch = get_branch()
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


def get_git_version(is_tagged: bool) -> str:
    git_version = subprocess.check_output(command.split()).decode('utf-8').strip()
    if is_tagged:
        return format_version(version=git_version, fmt=fmt_tagged)
    return format_version(version=git_version, fmt=fmt_dev, is_dev=True)

def check_if_tagged() -> bool:
    output = subprocess.check_output(is_tagged_cmd.split()).decode('utf-8').strip()
    return output != ""

def get_pkg_info_version(pkg_info_file):
    pkg = get_distribution(PACKAGE_NAME)
    return pkg.version


def get_version() -> str:
    version   = "0.13.0"
    pkg_info  = os.path.join(CURRENT_DIR, "{}.egg-info".format(PACKAGE_NAME), "PKG-INFO")
    git_dir   = os.path.join(CURRENT_DIR, ".git")
    if os.path.isdir(git_dir):
        is_tagged = False
        try:
            is_tagged = check_if_tagged()
        except Exception:
            is_tagged = False

        try:
            return get_git_version(is_tagged)
        except Exception:
            pass

    if os.path.isfile(pkg_info):
        return get_pkg_info_version(pkg_info)

    return version

version = get_version()
print(version)
cmdclass = {
    'build_ext': BuildLibrary,
}

setup(
    distclass=LiefDistribution,
    ext_modules=[Module(PACKAGE_NAME)],
    cmdclass=cmdclass,
    version=version
)
