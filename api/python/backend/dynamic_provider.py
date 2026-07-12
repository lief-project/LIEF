from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from scikit_build_core._logging import rich_print
from setup import BINDING_DIR
from versioning import Versioning


def dynamic_metadata(
    settings: Mapping[str, Any],
    project: Mapping[str, Any],
) -> dict[str, Any]:
    version = Versioning().get_version()
    rich_print("{green}LIEF Version: {version}", version=version)
    return {
        "version": version,
        "readme": (BINDING_DIR / "README.rst").as_posix(),
    }
