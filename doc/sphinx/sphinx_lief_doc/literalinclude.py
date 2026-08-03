from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from sphinx.directives.code import LiteralInclude as SphinxLiteralInclude

_LANGUAGES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "cpp",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".py": "python",
    ".pyi": "python",
    ".rs": "rust",
}


class LiteralInclude:
    """Build a Sphinx ``literalinclude`` directive from a MyST substitution.

    The optional ``marker`` argument follows the convention used by LIEF's
    examples: ``lief-doc: <marker>-start`` and ``lief-doc: <marker>-end``.
    It also enables automatic dedenting and infers the lexer from the source
    file's extension.
    """

    def __repr__(self) -> str:
        return "LiteralInclude()"

    def __eq__(self, other: object) -> bool:
        return type(self) is type(other)

    def __call__(
        self,
        filename: str,
        marker: str | None = None,
        /,
        **options: Any,
    ) -> str:
        filename = _single_line("filename", filename)
        normalized = {name.replace("_", "-"): value for name, value in options.items()}

        unknown = normalized.keys() - SphinxLiteralInclude.option_spec.keys()
        if unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"unsupported literalinclude option(s): {names}")

        if marker is not None:
            marker = _single_line("marker", marker)
            conflicts = normalized.keys() & {
                "start-after",
                "start-at",
                "end-before",
                "end-at",
            }
            if conflicts:
                names = ", ".join(sorted(conflicts))
                raise ValueError(
                    f"marker cannot be combined with literalinclude option(s): {names}"
                )

            language = _infer_language(filename)
            if language is None and "language" not in normalized:
                raise ValueError(
                    f"cannot infer the language for {filename!r}; pass language=..."
                )

            defaults: dict[str, Any] = {}
            if language is not None:
                defaults["language"] = language
            defaults.update(
                {
                    "start-after": f"lief-doc: {marker}-start",
                    "end-before": f"lief-doc: {marker}-end",
                    "dedent": True,
                }
            )
            defaults.update(normalized)
            normalized = defaults

        lines = [f"```{{literalinclude}} {filename}"]
        for name, value in normalized.items():
            if value is False:
                continue
            if value is True or value is None:
                lines.append(f":{name}:")
                continue

            value = _single_line(name, str(value))
            lines.append(f":{name}: {json.dumps(value)}")
        lines.append("```")
        return "\n".join(lines)


def _single_line(name: str, value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{name} cannot be empty")
    if "\n" in value or "\r" in value:
        raise ValueError(f"{name} must fit on one line")
    return value


def _infer_language(filename: str) -> str | None:
    path = PurePosixPath(filename)
    if path.name == "CMakeLists.txt":
        return "cmake"
    return _LANGUAGES.get(path.suffix.lower())
