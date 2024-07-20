from __future__ import annotations
import shlex
import subprocess
import re
import sys
import os

from setup import ROOT_DIR
from scikit_build_core.settings.skbuild_read_settings import rich_print as _rich_print
from shutil import which
from typing import Optional

def rich_print(*args):
    if sys.platform.startswith("win"):
        # Workaround for:
        # KeyError: 'WinError'
        # File "[...]\scikit_build_core\_logging.py", line 122, in <genexpr>
        #   lambda m: "".join(colors()[x] for x in m.group(1).split()),
        return print(*args)
    return _rich_print(*args)

class Versioning:
    COMMAND         = '{git} describe --tags --long --dirty'
    GIT_BRANCH      = '{git} rev-parse --abbrev-ref HEAD'
    IS_TAGGED_CMD   = '{git} tag --list --points-at=HEAD'
    FMT_DEV         = '{tag}.dev0'
    FMT_TAGGED      = '{tag}'
    CMAKE_VERSION_R = r"set\(LIEF_VERSION_(MAJOR|MINOR|PATCH)\s\"(\d+)\"\)"

    def __init__(self):
        self._git = which("git")

    def _exec_git_cmd(self, cmd: str, **kwargs) -> str:
        args = dict(kwargs)
        args["git"] = self._git
        cmd_list = shlex.split(cmd.format(**args))
        return subprocess.check_output(cmd_list,
                                       text=True,
                                       cwd=ROOT_DIR.as_posix()).strip()

    def has_git(self) -> bool:
        return self._git is not None and (ROOT_DIR / ".git").is_dir()

    def get_branch(self) -> Optional[str]:
        if not self.has_git():
            return None

        try:
            return self._exec_git_cmd(Versioning.GIT_BRANCH)
        except subprocess.SubprocessError as e:
            rich_print(f"[red]Error: {e}")
            return None

    def format_version(self, version: str, fmt: str, is_dev: bool = False):
        branch = self.get_branch()
        if branch is not None and branch.startswith("release-"):
            _, version = branch.split("release-")
            return version

        if branch is not None and branch.startswith("release/"):
            _, version = branch.split("release/")
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

    def version_from_git(self) -> Optional[str]:
        if not self.has_git():
            return None

        try:
            is_tagged = self._exec_git_cmd(Versioning.IS_TAGGED_CMD) != ""
            git_version = self._exec_git_cmd(Versioning.COMMAND)
            if is_tagged:
                return self.format_version(version=git_version, fmt=Versioning.FMT_TAGGED)
            return self.format_version(version=git_version, fmt=Versioning.FMT_DEV, is_dev=True)
        except Exception as e:
            rich_print(f"[red]Error: {e}")
            return None

    def version_from_cmake(self) -> Optional[str]:
        main_cmake = ROOT_DIR / "CMakeLists.txt"
        cmakefile = main_cmake.read_text()
        major: Optional[int] = None
        minor: Optional[int] = None
        patch: Optional[int] = None

        itre = re.finditer(Versioning.CMAKE_VERSION_R, cmakefile,
                           flags=re.MULTILINE)

        for cmake_version in itre:
            typ, value = cmake_version.groups()
            typ = typ.lower()
            if typ == "major":
                major = int(value)
            elif typ == "minor":
                minor = int(value)
            elif typ == "patch":
                patch = int(value)

        if any(e is None for e in (major, minor, patch)):
            return None

        return f"{major}.{minor}.{patch}"

    def get_version(self) -> str:
        if version := os.getenv("LIEF_VERSION_ENV"):
            return version

        if version := self.version_from_git():
            return version

        if version := self.version_from_cmake():
            return version

        raise RuntimeError("Can't determine version")
