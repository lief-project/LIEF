import re
import inspect
from typing import Any

from sphinx.util import logging
from sphinx.util.inspect import (
    getdoc,
    signature_from_str
)

from sphinx.application import Sphinx

RE_INST = re.compile(r"\s=\s<.*\sobject\sat[^>]*>")

logger = logging.getLogger("lief-python-typing")

def clean_nanobind_typehint(typehint: str) -> str:
    typehint = RE_INST.sub("", typehint)
    typehint = typehint.replace("_lief.", "")
    return typehint

def process_function_signature(signature: inspect.Signature, has_overload: bool):
    args = "(*args)"
    if not has_overload:
        args_str = []
        for name, hint in signature.parameters.items():
            if hint.annotation == inspect.Parameter.empty:
                args_str.append(name)
            else:
                args_str.append(f"{name}: {hint.annotation}")

        args = "(" + ",".join(args_str) + ")"

    if signature.return_annotation == inspect.Parameter.empty:
        return args, None

    return args, signature.return_annotation

def process_property(name: str, obj, options, signature: str,
                     return_annotation: str):
    """
    Get the nanobind typehint for a property
    """
    if not hasattr(obj, "fget"):
        return signature, return_annotation

    fget = getattr(obj, "fget")
    typestr = getdoc(fget)
    if typestr is None:
        return signature, return_annotation

    lines = typestr.splitlines()

    if len(lines) == 0:
        return signature, return_annotation

    try:
        hint = clean_nanobind_typehint(lines[0])
        sig = signature_from_str(hint)
        return_annotation = sig.return_annotation
        if return_annotation == inspect.Parameter.empty:
            logger.warn(f"Can't generate annotation for {name}")
            return_annotation = None

        return "()", return_annotation
    except Exception:
        logger.warning(f"Error with {name}: {lines[0]}")

    return signature, return_annotation


def process_function(name: str, obj, options, signature: str,
                     return_annotation: str):
    """
    Get the nanobind typehint for a function
    """
    typestr = getdoc(obj)
    if typestr is None:
        return signature, return_annotation

    lines = typestr.splitlines()

    if len(lines) == 0:
        return signature, return_annotation

    empty_idx = 0
    try:
        empty_idx = lines.index('')
    except ValueError:
        pass

    is_overloaded = empty_idx > 1

    rettypes = set()
    arg = None
    for idx, line in enumerate(lines):
        if len(line) == 0:
            break
        try:
            hint = clean_nanobind_typehint(line)
            signature = signature_from_str(hint)
            arg, ret = process_function_signature(signature, is_overloaded)
            rettypes.add(str(ret))
        except Exception as e:
            logger.warn(f"Error with {name}: {line} ({e})")

    if len(rettypes) == 0 or arg is None:
        return signature, return_annotation

    if len(rettypes) == 1:
        return arg, rettypes.pop()

    return arg, " | ".join(rettypes)

def on_process_signature(app, what: str, name: str, obj: Any,
                         options, signature: str, return_annotation: str):

    # autodoc is great for auto generating documentation of regular packages
    # but it has some limitation (like the properties) for native Python
    # bindings.
    #
    # This event listener generate the type hint for our nanobind-based bindings
    if what == "property":
        return process_property(name, obj, options, signature, return_annotation)

    if what == "function":
        return process_function(name, obj, options, signature, return_annotation)

    if what == "attribute":
        if hasattr(obj, "__call__"):
            return process_function(name, obj, options, signature, return_annotation)

    return signature, return_annotation

def autodoc_process_docstring(app, what, name, obj, options, lines: list[str]):
    if len(lines) > 2 or len(lines) == 0:
        return
    line = lines[0]

    if line.startswith("(self)"):
        lines[:] = []
    return

def setup(app: Sphinx):
    app.connect('autodoc-process-signature', on_process_signature)
    app.connect('autodoc-process-docstring', autodoc_process_docstring)

