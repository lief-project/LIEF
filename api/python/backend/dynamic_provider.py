from __future__ import annotations
from setup import BINDING_DIR
from versioning import Versioning
from scikit_build_core.settings.skbuild_read_settings import rich_print

def dynamic_metadata(field, config) -> str:
    if field == "version":
        version = Versioning().get_version()
        rich_print(f"[green]LIEF Version: {version}")
        return version

    if field == "readme":
        return (BINDING_DIR / "README.rst").as_posix()
