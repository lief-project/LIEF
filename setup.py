import os
import sys
import platform
import subprocess
import setuptools
import pathlib
from pkg_resources import Distribution, get_distribution
from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext, copy_file
from distutils import log

from distutils.version import LooseVersion

MIN_SETUPTOOLS_VERSION = "31.0.0"
assert (LooseVersion(setuptools.__version__) >= LooseVersion(MIN_SETUPTOOLS_VERSION)), "LIEF requires a setuptools version '{}' or higher (pip install setuptools --upgrade)".format(MIN_SETUPTOOLS_VERSION)

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
PACKAGE_NAME = "lief"

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
        filename = self.get_ext_filename(fullname)

        jobs = self.parallel if self.parallel else 1

        source_dir                     = ext.sourcedir
        build_temp                     = self.build_temp
        extdir                         = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        cmake_library_output_directory = os.path.abspath(os.path.dirname(build_temp))
        cfg                            = 'Debug' if self.debug else 'Release'
        is64                           = sys.maxsize > 2**32

        cmake_args = [
            '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={}'.format(cmake_library_output_directory),
            '-DPYTHON_EXECUTABLE={}'.format(sys.executable),
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

        if platform.system() == "Windows":
            cmake_args += [
                '-DCMAKE_BUILD_TYPE={}'.format(cfg),
                '-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_{}={}'.format(cfg.upper(), cmake_library_output_directory),
                '-DLIEF_USE_CRT_RELEASE=MT',
            ]
            cmake_args += ['-A', 'x64'] if is64 else []

            # Specific to appveyor
            #if os.getenv("APPVEYOR", False):
            #    build_args += ['--', '/v:m']
            #    logger = os.getenv("MSBuildLogger", None)
            #    if logger:
            #        build_args += ['/logger:{}'.format(logger)]
            #else:
            build_args += ['--', '/m']
        else:
            cmake_args += ['-DCMAKE_BUILD_TYPE={}'.format(cfg)]

        env = os.environ.copy()

        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)

        build_with_ninja = False
        if self.has_ninja() and self.distribution.ninja:
            cmake_args += ["-G", "Ninja"]
            build_with_ninja = True


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
            targets['doc'] = "doc-lief"

        if platform.system() == "Windows":
            build_cmd = ['cmake', '--build', '.', '--target', "lief_samples"] + build_args
            #log.info(" ".join(build_cmd))

            if self.distribution.lief_test:
                subprocess.check_call(['cmake', '--build', '.', '--target', "lief_samples"] + build_args, cwd=self.build_temp, env=env)
                subprocess.check_call(configure_cmd, cwd=self.build_temp, env=env)
                subprocess.check_call(['cmake', '--build', '.', '--target', "ALL_BUILD"] + build_args, cwd=self.build_temp, env=env)
                subprocess.check_call(['cmake', '--build', '.', '--target', "check-lief"] + build_args, cwd=self.build_temp, env=env)
            else:
                subprocess.check_call(['cmake', '--build', '.', '--target', targets['python_bindings']] + build_args, cwd=self.build_temp, env=env)

            if 'sdk' in targets:
                subprocess.check_call(['cmake', '--build', '.', '--target', targets['sdk']] + build_args, cwd=self.build_temp, env=env)

        else:
            if build_with_ninja:
                if self.distribution.lief_test:
                    subprocess.check_call(['ninja', "lief_samples"], cwd=self.build_temp)
                    subprocess.check_call(configure_cmd, cwd=self.build_temp)
                    subprocess.check_call(['ninja'], cwd=self.build_temp)
                    subprocess.check_call(['ninja', "check-lief"], cwd=self.build_temp)
                else:
                    subprocess.check_call(['ninja', targets['python_bindings']], cwd=self.build_temp)

                if 'sdk' in targets:
                    subprocess.check_call(['ninja', targets['sdk']], cwd=self.build_temp)

                if 'doc' in targets:
                    try:
                        subprocess.check_call(['ninja', targets['doc']], cwd=self.build_temp)
                    except Exception as e:
                        log.error("Documentation failed: %s" % e)
            else:
                log.info("Using {} jobs".format(jobs))
                if self.distribution.lief_test:
                    subprocess.check_call(['make', '-j', str(jobs), "lief_samples"], cwd=self.build_temp)
                    subprocess.check_call(configure_cmd, cwd=self.build_temp)
                    subprocess.check_call(['make', '-j', str(jobs), "all"], cwd=self.build_temp)
                    subprocess.check_call(['make', '-j', str(jobs), "check-lief"], cwd=self.build_temp)
                else:
                    subprocess.check_call(['make', '-j', str(jobs), targets['python_bindings']], cwd=self.build_temp)

                if 'sdk' in targets:
                    subprocess.check_call(['make', '-j', str(jobs), targets['sdk']], cwd=self.build_temp)

                if 'doc' in targets:
                    try:
                        subprocess.check_call(['make', '-j', str(jobs), targets['doc']], cwd=self.build_temp)
                    except Exception as e:
                        log.error("Documentation failed: %s" % e)
        pylief_dst  = os.path.join(self.build_lib, self.get_ext_filename(self.get_ext_fullname(ext.name)))


        libsuffix = pylief_dst.split(".")[-1]

        pylief_path = os.path.join(cmake_library_output_directory, "{}.{}".format(PACKAGE_NAME, libsuffix))
        if platform.system() == "Windows":
            pylief_path = os.path.join(cmake_library_output_directory, "Release", "api", "python", "Release", "{}.{}".format(PACKAGE_NAME, libsuffix))

        if not os.path.exists(self.build_lib):
            os.makedirs(self.build_lib)

        log.info("Copying {} into {}".format(pylief_path, pylief_dst))
        copy_file(
                pylief_path, pylief_dst, verbose=self.verbose,
                dry_run=self.dry_run)


        # SDK
        # ===
        if self.distribution.sdk:
            sdk_path = list(pathlib.Path(self.build_temp).rglob("LIEF-*.{}".format(self.sdk_suffix())))
            if len(sdk_path) == 0:
                log.error("Unable to find SDK archive")
                sys.exit(1)

            sdk_path = str(sdk_path.pop())
            sdk_output = str(pathlib.Path(CURRENT_DIR) / "build")

            copy_file(
                sdk_path, sdk_output, verbose=self.verbose,
                dry_run=self.dry_run)



# From setuptools-git-version
command       = 'git describe --tags --long --dirty'
is_tagged_cmd = 'git tag --list --points-at=HEAD'
fmt_dev       = '{tag}.dev0'
fmt_tagged    = '{tag}'

def format_version(version: str, fmt: str = fmt_dev, is_dev: bool = False):
    parts = version.split('-')
    assert len(parts) in (3, 4)
    dirty = len(parts) == 4
    tag, count, sha = parts[:3]
    MA, MI, PA = map(int, tag.split(".")) # 0.9.0 -> (0, 9, 0)

    if is_dev:
        tag = "{}.{}.{}".format(MA, MI + 1, 0)

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
    version   = "0.0.0"
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
