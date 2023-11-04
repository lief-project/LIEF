#!/usr/bin/env python
import os
import sys
import platform
import re
import subprocess
import stat
import time
from typing import Optional, Tuple
from pathlib import Path
from subprocess import Popen

import importlib.util

def import_from_file(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def lief_samples_dir() -> str:
    dir = os.getenv("LIEF_SAMPLES_DIR", None)
    if dir is None:
        print("LIEF_SAMPLES_DIR is not set", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(dir):
        print("{} is not a valid directory".format(dir), file=sys.stderr)
        sys.exit(1)
    return dir

def get_sample(filename):
    fullpath = os.path.join(lief_samples_dir(), filename)

    assert os.path.exists(fullpath)
    assert os.path.isfile(fullpath)
    return fullpath

def get_compiler():
    compiler = os.getenv("CC", "/usr/bin/cc")
    if not os.path.exists(compiler):
        raise RuntimeError("Unable to find a compiler")
    return compiler

def is_linux() -> bool:
    return sys.platform.startswith("linux")

def is_osx() -> bool:
    return sys.platform.startswith("darwin")

def is_windows() -> bool:
    return sys.platform.startswith("win")

def is_x86_64() -> bool:
    machine = platform.machine().lower()
    return machine in ("x86_64", "amd64")

def is_apple_m1() -> bool:
    return is_aarch64() and is_osx()

def is_aarch64() -> bool:
    machine = platform.machine().lower()
    return machine in ("aarch64", "arm64")

def glibc_version() -> Tuple[int, int]:
    try:
        out = subprocess.check_output(["ldd", "--version"]).decode("ascii")
        version_str = re.search(r" (\d\.\d+)\n", out).group(1)
        major, minor = version_str.split(".")
        return (int(major), int(minor))
    except (OSError, AttributeError):
        return (0, 0)


def has_recent_glibc() -> bool:
    """Check if we have at least GLIBC 2.17 (2012)"""
    major, minor = glibc_version()
    return major == 2 and minor >= 17

def is_64bits_platform() -> bool:
    return sys.maxsize > 2**32

def chmod_exe(path):
    if isinstance(path, Path):
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    elif isinstance(path, str):
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return

def sign(path):
    """
    Sign the binary with an ad-hoc signature
    """
    CMD = ["/usr/bin/codesign", "-vv", "--verbose", "--force", "-s", "-"]
    CMD.append(path)
    print("Signing {}".format(path))
    with subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        stdout = proc.stdout.read().decode("utf8")
        print(stdout)

def is_github_ci() -> bool:
    return os.getenv("GITHUB_ACTIONS", None) is not None

def _win_gui_exec(executable: Path, timeout: int = 60) -> Optional[Tuple[int, str]]:
    popen_args = {
        "universal_newlines": True,
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "creationflags": 0x8000000  # win32con.CREATE_NO_WINDOW
    }

    with Popen(["START", executable.as_posix()], **popen_args) as proc:
        time.sleep(3)
        with Popen(["taskkill", "/im", executable.name], **popen_args) as kproc:
            try:
                pstdout, _ = proc.communicate(timeout)
                print("pstdout:", pstdout)
                kstdout, _ = kproc.communicate(timeout)
                print("kstdout", kstdout)
                return (kproc.returncode, pstdout + kstdout)
            except subprocess.TimeoutExpired:
                return None

def win_exec(executable: Path, timeout: int = 60, gui: bool = True) -> Optional[Tuple[int, str]]:
    if not is_windows():
        return None

    if gui:
        return _win_gui_exec(executable, timeout)

    popen_args = {
        "universal_newlines": True,
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "creationflags": 0x8000000  # win32con.CREATE_NO_WINDOW
    }

    with Popen([executable.as_posix()], **popen_args) as proc:
        try:
            stdout, _ = proc.communicate(timeout)
            print("stdout:", stdout)
            return (proc.returncode, stdout)
        except subprocess.TimeoutExpired:
            return None
