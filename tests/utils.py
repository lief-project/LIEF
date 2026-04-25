import importlib.util
import json
import math
import os
import platform
import re
import stat
import subprocess
import sys
import sysconfig
import time
from functools import lru_cache, wraps
from pathlib import Path
from subprocess import Popen
from typing import Any, List, Optional, Tuple, TypeAlias, cast

import lief

CheckLayoutInput: TypeAlias = (
    str
    | Path
    | lief.ELF.Binary
    | lief.PE.Binary
    | lief.MachO.Binary
    | lief.COFF.Binary
    | None
)


def check_objc_dump(metadata: lief.objc.Metadata, file: Path) -> bool:
    """Verify that the Objective-C metadata matches the expected content in file."""
    decl_opt = lief.objc.DeclOpt()
    decl_opt.show_annotations = False
    assert metadata.to_decl(decl_opt) == file.read_text()
    return True


def import_from_file(module_name: str, file_path: Path):
    """Dynamically import a Python module from a filepath."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@lru_cache
def lief_samples_dir() -> Path:
    """Return the directory where test binaries are located"""
    samples_dir = os.getenv("LIEF_SAMPLES_DIR")
    if samples_dir is None:
        print("LIEF_SAMPLES_DIR is not set", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(samples_dir):
        print(f"{samples_dir} is not a valid directory", file=sys.stderr)
        sys.exit(1)
    return Path(samples_dir)


@lru_cache
def lief_build_dir() -> Path:
    build_dir = os.getenv("LIEF_BUILD_DIR")
    if build_dir is None:
        print("LIEF_BUILD_DIR is not set", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(build_dir):
        print(f"{build_dir} is not a valid directory", file=sys.stderr)
        sys.exit(1)
    return Path(build_dir)


def get_sample(filename: str | Path) -> str:
    """
    Retrieve a sample from its name or relative path from the sample directory
    """
    fullpath = lief_samples_dir() / filename
    assert fullpath.is_file()
    return str(fullpath)


def get_path_sample(name: str) -> Path:
    """Same as get_sample() but returning a Path"""
    return Path(get_sample(name))


def parse_elf(
    filename: Any, config: lief.ELF.ParserConfig | None = None
) -> lief.ELF.Binary:
    """Parse an ELF binary from a sample name or raw input"""
    target_filename = filename
    if isinstance(filename, (str, Path)):
        target_filename = get_sample(str(filename))
    if config is None:
        elf = lief.ELF.parse(target_filename)
    else:
        elf = lief.ELF.parse(target_filename, config)

    return cast(lief.ELF.Binary, elf)


def parse_pe(
    filename: Any, config: lief.PE.ParserConfig | None = None
) -> lief.PE.Binary:
    """Parse a PE binary from a sample name or raw input"""
    target_filename = filename
    if isinstance(filename, (str, Path)):
        target_filename = get_sample(str(filename))
    if config is None:
        pe = lief.PE.parse(target_filename)
    else:
        pe = lief.PE.parse(target_filename, config)

    return cast(lief.PE.Binary, pe)


def parse_macho(
    filename: Any, config: lief.MachO.ParserConfig | None = None
) -> lief.MachO.FatBinary:
    """Parse a Mach-O binary from a sample name or raw input"""
    target_filename = filename
    if isinstance(filename, (str, Path)):
        target_filename = get_sample(str(filename))
    if config is None:
        macho = lief.MachO.parse(target_filename)
    else:
        macho = lief.MachO.parse(target_filename, config)

    return cast(lief.MachO.FatBinary, macho)


def parse_coff(filename: Any, config: Any | None = None) -> lief.COFF.Binary:
    """Parse a COFF binary from a sample name or raw input"""
    target_filename = filename
    if isinstance(filename, (str, Path)):
        target_filename = get_sample(str(filename))
    if config is None:
        coff = lief.COFF.parse(target_filename)
    else:
        coff = lief.COFF.parse(target_filename, config)

    return cast(lief.COFF.Binary, coff)


def load_dwarf(filename: str) -> lief.dwarf.DebugInfo:
    """Load DWARF debug information from a sample file."""
    return cast(lief.dwarf.DebugInfo, lief.dwarf.load(get_sample(filename)))


def get_debug_info(binary: lief.Binary) -> lief.dwarf.DebugInfo:
    """Extract DWARF debug information from a parsed binary."""
    dbg = binary.debug_info
    assert dbg is not None
    return cast(lief.dwarf.DebugInfo, dbg)


def get_compiler():
    """Return the path to the C compiler"""
    compiler = os.getenv("CC", "/usr/bin/cc")
    if not os.path.exists(compiler):
        raise RuntimeError("Unable to find a compiler")
    return compiler


def is_linux() -> bool:
    """Check if the current platform is Linux."""
    return sys.platform.startswith("linux")


def is_osx() -> bool:
    """Check if the current platform is macOS."""
    return sys.platform.startswith("darwin")


def is_windows() -> bool:
    """Check if the current platform is Windows."""
    return sys.platform.startswith("win")


def is_x86_64() -> bool:
    """Check if the current machine architecture is x86_64."""
    machine = platform.machine().lower()
    return machine in ("x86_64", "amd64")


def is_windows_x86_64():
    """Check if the current platform is Windows on x86_64."""
    return is_windows() and is_x86_64()


def is_apple_m1() -> bool:
    """Check if the current platform is macOS on Apple Silicon (AArch64)."""
    return is_aarch64() and is_osx()


def is_aarch64() -> bool:
    """Check if the current machine architecture is arm64"""
    machine = platform.machine().lower()
    return machine in ("aarch64", "arm64")


@lru_cache(maxsize=1)
def glibc_version() -> Tuple[int, int]:
    """Return the system glibc version as a (major, minor)"""
    try:
        out = subprocess.check_output(["ldd", "--version"]).decode("ascii")
        version_str = re.search(r" (\d\.\d+)\n", out).group(1)  # type: ignore
        major, minor = version_str.split(".")
        return (int(major), int(minor))
    except (OSError, AttributeError):
        return (0, 0)


def has_recent_glibc() -> bool:
    """Check if we have at least GLIBC 2.17 (2012)"""
    major, minor = glibc_version()
    return major == 2 and minor >= 17


def is_64bits_platform() -> bool:
    """Check if the current interpreter is running on a 64-bit platform."""
    return sys.maxsize > 2**32


def chmod_exe(path: Path | str):
    """Add the executable permission bit to the given file."""
    if isinstance(path, Path):
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    elif isinstance(path, str):
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


def sign(path):
    """Sign the binary with an ad-hoc signature"""
    codesign_cmd = ["/usr/bin/codesign", "-vv", "--verbose", "--force", "-s", "-", path]
    with subprocess.Popen(
        codesign_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as proc:
        stdout = proc.stdout.read().decode("utf8")  # type: ignore
        print(stdout)


def is_github_ci() -> bool:
    """Check if the code is running in a GitHub Actions CI environment."""
    return os.getenv("GITHUB_ACTIONS", None) is not None


def is_server_ci() -> bool:
    """Check if the code is running on the GitLab server CI."""
    return os.getenv("CI_SERVER_HOST", "") == "gitlab.server"


def ci_runner_tags() -> list[str]:
    """Return the list of CI runner tags"""
    value = os.getenv("CI_RUNNER_TAGS", None)
    if value is None:
        return []
    return json.loads(value)


def ci_runner_arch() -> str:
    """Return the CI runner executable architecture"""
    return os.getenv("CI_RUNNER_EXECUTABLE_ARCH", "")


def has_private_samples() -> bool:
    """Check if private test samples are available."""
    return (lief_samples_dir() / "private").is_dir()


def has_dyld_shared_cache_samples():
    """Check if dyld shared cache samples are available"""
    if (lief_samples_dir() / "dyld_shared_cache").is_dir():
        return True

    dsc_samples_dir = os.getenv("LIEF_DSC_SAMPLES_DIR", None)
    if dsc_samples_dir is None:
        return False

    return Path(dsc_samples_dir).is_dir()


def get_dsc_sample(suffix: str) -> Path:
    """Return the path to a dyld shared cache sample by its relative suffix."""
    dir1 = lief_samples_dir() / "dyld_shared_cache"
    if dir1.is_dir():
        return dir1 / suffix

    dsc_samples_dir = os.environ.get("LIEF_DSC_SAMPLES_DIR")
    if dsc_samples_dir is None:
        raise RuntimeError("Missing 'LIEF_DSC_SAMPLES_DIR'")

    return Path(dsc_samples_dir).resolve().absolute() / suffix


def _win_gui_exec_server(
    executable: Path, timeout: int = 60
) -> Optional[Tuple[int, str]]:
    """Execute a Windows GUI application with a hidden window"""
    si = subprocess.STARTUPINFO()  # type: ignore
    si.dwFlags = subprocess.STARTF_USESTDHANDLES | subprocess.STARTF_USESHOWWINDOW  # type: ignore
    si.wShowWindow = 0  # SW_HIDE
    popen_args: dict[str, Any] = {
        "universal_newlines": True,
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "creationflags": subprocess.CREATE_NO_WINDOW,  # type: ignore
        "startupinfo": si,
    }
    with Popen([executable.as_posix()], **popen_args) as proc:
        time.sleep(3)
        with Popen(
            ["tasklist", "/FI", f"IMAGENAME eq {executable.name}"], **popen_args
        ) as tasklist:
            pstdout, _ = tasklist.communicate(timeout=timeout)
            print("tasklist:", pstdout)
        with Popen(["taskkill", "/F", "/IM", executable.name], **popen_args) as kproc:
            try:
                pstdout, _ = proc.communicate(timeout=timeout)
                print("pstdout:", pstdout)
                kstdout, _ = kproc.communicate(timeout=timeout)
                print("kstdout", kstdout)
                return (kproc.returncode, pstdout + kstdout)
            except subprocess.TimeoutExpired:
                return None


def _win_gui_exec(executable: Path, timeout: int = 60) -> Optional[Tuple[int, str]]:
    """Execute a Windows GUI application"""
    if is_server_ci():
        return _win_gui_exec_server(executable, timeout)

    popen_args: dict[str, Any] = {
        "universal_newlines": True,
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "creationflags": subprocess.CREATE_NO_WINDOW,  # type: ignore
    }
    with Popen(["START", executable.as_posix()], **popen_args) as proc:
        time.sleep(3)
        with Popen(["taskkill", "/im", executable.name], **popen_args) as kproc:
            try:
                pstdout, _ = proc.communicate(timeout=timeout)
                print("pstdout:", pstdout)
                kstdout, _ = kproc.communicate(timeout=timeout)
                print("kstdout", kstdout)
                return (kproc.returncode, pstdout + kstdout)
            except subprocess.TimeoutExpired:
                return None


def win_exec(
    executable: Path,
    timeout: int = 60,
    gui: bool = True,
    universal_newlines: bool = True,
    args: List[str] = [],
) -> Optional[Tuple[int, str]]:
    """
    Execute a Windows binary (GUI or console) and return its exit code and output.
    """
    if not is_windows():
        return None

    executable.chmod(executable.stat().st_mode | stat.S_IEXEC)

    if gui:
        return _win_gui_exec(executable, timeout)

    popen_args: dict[str, Any] = {
        "universal_newlines": universal_newlines,
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "creationflags": 0x8000000,  # win32con.CREATE_NO_WINDOW
    }

    with Popen([executable.as_posix(), *args], **popen_args) as proc:
        try:
            stdout, _ = proc.communicate(timeout=timeout)
            print("stdout:", stdout)
            return (proc.returncode, stdout)
        except subprocess.TimeoutExpired:
            return None


def normalize_path(path: str) -> str:
    """Normalize a filepath by replacing backslashes with forward slashes."""
    return path.replace("\\", "/")


def check_layout(target: CheckLayoutInput):
    """
    Verify the internal layout consistency of an ELF, PE, or Mach-O binary.

    This function can be used to ensure a high consistency of the binary
    when it can't be executed.
    """
    if target is None:
        return

    if isinstance(target, (str, Path)):
        target_bin = cast(CheckLayoutInput, lief.parse(str(target)))
    else:
        target_bin = target

    assert target_bin is not None

    if isinstance(target_bin, lief.ELF.Binary):
        check, msg = lief.ELF.check_layout(target_bin)
        assert check, msg
        return

    if isinstance(target_bin, lief.PE.Binary):
        check, msg = lief.PE.check_layout(target_bin)
        assert check, msg
        return

    if isinstance(target_bin, lief.MachO.Binary):
        check, msg = lief.MachO.check_layout(target_bin)
        assert check, msg
        return

    raise RuntimeError("Invalid binary")


def disable_logging(func):
    """
    Decorator to disable LIEF logger for the whole function
    """

    @wraps(func)
    def without_logging(*args, **kwargs):
        with lief.logging.level_scope(lief.logging.LEVEL.OFF):
            return func(*args, **kwargs)

    return without_logging


def lief_logging(level: lief.logging.LEVEL):
    """
    Decorator to change the log level within the scope of the function
    """

    def decorator(func):
        @wraps(func)
        def with_level(*args, **kwargs):
            with lief.logging.level_scope(level):
                return func(*args, **kwargs)

        return with_level

    return decorator


def convert_size(size_bytes: int) -> str:
    """
    Convert the input bytes into a human-readable size.
    """
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"


def is_free_threaded() -> bool:
    """Check if the current interpreter supports free-threading"""
    return sysconfig.get_config_var("Py_GIL_DISABLED") == "1" and lief.__free_threaded__
