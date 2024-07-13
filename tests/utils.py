#!/usr/bin/env python
import lief
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

def check_objc_dump(metadata: lief.objc.Metadata, file: Path) -> bool:
    assert metadata.to_decl() == file.read_text()
    return True

def import_from_file(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def lief_samples_dir() -> str:
    samples_dir = os.getenv("LIEF_SAMPLES_DIR", None)
    if samples_dir is None:
        print("LIEF_SAMPLES_DIR is not set", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(samples_dir):
        print(f"{samples_dir} is not a valid directory", file=sys.stderr)
        sys.exit(1)
    return samples_dir

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

def sign(path):
    """
    Sign the binary with an ad-hoc signature
    """
    CMD = ["/usr/bin/codesign", "-vv", "--verbose", "--force", "-s", "-"]
    CMD.append(path)
    print(f"Signing {path}")
    with subprocess.Popen(CMD, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        stdout = proc.stdout.read().decode("utf8")
        print(stdout)

def is_github_ci() -> bool:
    return os.getenv("GITHUB_ACTIONS", None) is not None

def is_server_ci() -> bool:
    return os.getenv('CI_SERVER_HOST', '') == 'gitlab.server'

def has_private_samples() -> bool:
    return (Path(lief_samples_dir()) / "private").is_dir()

def _win_gui_exec_server(executable: Path, timeout: int = 60) -> Optional[Tuple[int, str]]:
    si = subprocess.STARTUPINFO() # type: ignore[attr-defined]
    si.dwFlags = subprocess.STARTF_USESTDHANDLES | subprocess.STARTF_USESHOWWINDOW # type: ignore[attr-defined]
    si.wShowWindow = 0 # SW_HIDE
    popen_args = {
        "universal_newlines": True,
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "creationflags": subprocess.CREATE_NO_WINDOW, # type: ignore[attr-defined]
        "startupinfo": si,
    }
    with Popen([executable.as_posix()], **popen_args) as proc:
        time.sleep(3)
        with Popen(["tasklist", "/FI", f"IMAGENAME eq {executable.name}"], **popen_args) as tasklist: # type: ignore[call-overload]
            pstdout, _ = tasklist.communicate(timeout)
            print("tasklist:", pstdout)
        with Popen(["taskkill", '/F', '/IM', executable.name], **popen_args) as kproc: # type: ignore[call-overload]
            try:
                pstdout, _ = proc.communicate(timeout)
                print("pstdout:", pstdout)
                kstdout, _ = kproc.communicate(timeout)
                print("kstdout", kstdout)
                return (kproc.returncode, pstdout + kstdout)
            except subprocess.TimeoutExpired:
                return None

def _win_gui_exec(executable: Path, timeout: int = 60) -> Optional[Tuple[int, str]]:
    if is_server_ci():
        return _win_gui_exec_server(executable, timeout)

    popen_args = {
        "universal_newlines": True,
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "creationflags": subprocess.CREATE_NO_WINDOW, # type: ignore[attr-defined]
    }
    with Popen(["START", executable.as_posix()], **popen_args) as proc: # type: ignore[call-overload]
        time.sleep(3)
        with Popen(["taskkill", "/im", executable.name], **popen_args) as kproc: # type: ignore[call-overload]
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

    with Popen([executable.as_posix()], **popen_args) as proc: # type: ignore[call-overload]
        try:
            stdout, _ = proc.communicate(timeout)
            print("stdout:", stdout)
            return (proc.returncode, stdout)
        except subprocess.TimeoutExpired:
            return None

def normalize_path(path: str) -> str:
    return path.replace('\\', '/')
