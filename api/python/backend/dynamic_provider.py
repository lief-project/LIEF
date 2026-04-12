from __future__ import annotations

from scikit_build_core._logging import rich_print
from setup import BINDING_DIR
from versioning import Versioning


def dynamic_metadata(field, config) -> str | None:
    if field == "version":
        version = Versioning().get_version()
        rich_print("{green}LIEF Version: {version}", version=version)
        return version

    if field == "readme":
        return (BINDING_DIR / "README.rst").as_posix()
