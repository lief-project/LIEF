#!/usr/bin/env python
# -*- coding: utf-8 -*-
import inspect
import lief
import os
import pathlib
import re
import sphinx
import sys

from datetime import date
from docutils import nodes
from docutils.nodes import Node
from pathlib import Path
from sphinx.ext.inheritance_diagram import InheritanceDiagram
from sphinx.util import logging
from sphinx.util.typing import OptionSpec
from typing import Any

from docutils.parsers.rst.roles import set_classes

from docutils.nodes import emphasis, title, raw

from sphinx.util import logging
from sphinx.util.inspect import (
    getdoc,
    signature_from_str
)

RE_INST = re.compile(r"\s=\s<.*\sobject\sat[^>]*>")

CURRENT_DIR = Path(__file__).parent
LIEF_ROOT_DIR = (CURRENT_DIR / "../..").resolve().absolute()

import sphinx_lief
import breathe

DOXYGEN_XML_PATH = os.getenv("LIEF_DOXYGEN_XML", None)
DOXYGEN_XML_PATH = pathlib.Path(DOXYGEN_XML_PATH).resolve().absolute()

extensions = [
    'sphinx.ext.mathjax',
    'sphinx.ext.autodoc',
    "sphinx_tabs.tabs",
    'sphinx.ext.inheritance_diagram',
    'breathe', 'sphinx_lief'
]

def get_breathe_projects_source():
    LIEF_C_INCLUDE = LIEF_ROOT_DIR / "api/c/include"
    files = []
    for file in LIEF_C_INCLUDE.rglob("*.h"):
        files.append(file.relative_to(LIEF_C_INCLUDE))
    return (LIEF_C_INCLUDE.as_posix(), files)

PREDEFINED = (
    "LIEF_API=",
    "LIEF_LOCAL=",
    "__cplusplus",
)

EXPAND_AS_DEFINED = (
    "_LIEF_EI",
    "_LIEF_EN",
    "_LIEF_EN_2",
)
breathe_projects = {
    "lief": DOXYGEN_XML_PATH,
}

breathe_domain_by_extension = {
    "h" : "c",
    "hpp" : "cpp",
}

breathe_doxygen_config_options = {
    "WARN_IF_UNDOCUMENTED": "NO",
    "MACRO_EXPANSION": "YES",
    'PREDEFINED': " ".join(PREDEFINED),
    'EXPAND_AS_DEFINED': " ".join(EXPAND_AS_DEFINED)
}

# This is used for generating the C API
breathe_projects_source = {
    "lief" : get_breathe_projects_source()
}

breathe_default_project = "lief"

logger = logging.getLogger("lief-doc")
# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

source_suffix = '.rst'

master_doc = 'index'
gh_org = "lief-project"
gh_repo = "LIEF"

project    = 'LIEF'
html_title = "LIEF Documentation"
copyright  = '2020, Quarkslab'
author     = 'Romain Thomas'

LIEF_VERSION_ENV = "LIEF_VERSION"

version = os.getenv(LIEF_VERSION_ENV) or (lief.__tag__ if lief.__is_tagged__ else lief.__version__)
release = os.getenv(LIEF_VERSION_ENV) or lief.__version__
commit  = lief.__commit__

language = "en"
autoclass_content = 'both'
autodoc_default_options = {
    'exclude-members': '@entries',
    'undoc-members': True,
    'inherited-members': False,
    'show-inheritance': False,
    'undoc-members': True,
    'members': True,
}

breathe_default_members = ('members', 'protected-members', 'undoc-members')
breathe_show_enumvalue_initializer = True

#exclude_patterns = [
#    "tutorials/*.rst",
#    "changelog.rst",
#    "formats/*.rst",
#    "api/python/abstract.rst",
#    "api/c/*.rst",
#    "api/cpp/*.rst",
#    "api/python/pe.rst",
#    "api/python/macho.rst",
#    "api/python/oat.rst",
#    "api/python/vdex.rst",
#    "api/python/dex.rst",
#]

# -- Options for HTML output ----------------------------------------------
def commit_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    commit_link = nodes.reference("", text[:7],
                                  refuri=f"https://github.com/{gh_org}/{gh_repo}/commit/{text}",
                                  **options)

    return [commit_link], []

def pr_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    pr_link = nodes.reference("", '#' + text,
                              refuri=f"https://github.com/{gh_org}/{gh_repo}/pull/{text}",
                              **options)

    return [pr_link], []

def issue_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    issue_link = nodes.reference("", '#' + text,
                                 refuri=f"https://github.com/{gh_org}/{gh_repo}/issues/{text}",
                                 **options)

    return [issue_link], []

def github_user(name, rawtext, text, lineno, inliner, options={}, content=[]):
    issue_link = nodes.reference("", text, refuri=f"https://github.com/{text}",
                                 **options)

    return [issue_link], []

def xmark(role, rawtext, text, lineno, inliner, options={}, content=[]):
    options["format"] = "html"
    node = raw(text='<b class="fa-solid fa-xmark text-danger  me-1"></b>', **options)
    return [node], []

def fa_check(role, rawtext, text, lineno, inliner, options={}, content=[]):
    options["format"] = "html"
    node = raw(text='<b class="fa-solid fa-check text-success me-1"></b>', **options)
    return [node], []

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

def _on_process_signature(app, what: str, name: str, obj: Any,
                          options, signature: str, return_annotation: str):

    # autodoc is great for auto generating documentation of regular packages
    # but it has some limitation (like the properties) for native Python
    # bindings.
    #
    # This event listener generate the type hint for our nanobind-based bindings
    if what == "property":
        return process_property(name, obj, options, signature, return_annotation)
    elif what == "function":
        return process_function(name, obj, options, signature, return_annotation)
    elif what == "attribute":
        if hasattr(obj, "__call__"):
            return process_function(name, obj, options, signature, return_annotation)

    return signature, return_annotation

def _autodoc_process_docstring(app, what, name, obj, options, lines: list[str]):
    if len(lines) > 2 or len(lines) == 0:
        return
    line = lines[0]

    if line.startswith("(self)"):
        lines[:] = []
    return

class LIEFInheritanceDiagram(InheritanceDiagram):
    option_spec: OptionSpec = {
        **InheritanceDiagram.option_spec,
        'depth': int
    }
    def _check_module(self, module, obj, depth: int):
        if not module.__name__.startswith("lief"):
            return []

        classes = []
        for name, member in inspect.getmembers(module):
            if inspect.isclass(member) and issubclass(member, obj):
                mro = inspect.getmro(member)
                if (0 < depth and mro.index(obj) <= depth) or depth == 0:
                    classes.append(f"{module.__name__}.{name}")
            if inspect.ismodule(member) and member != module:
                classes.extend(self._check_module(member, obj, depth))
        return list(set(classes))

    def run(self) -> list[Node]:
        cls = None
        classes = []
        depth = self.options.get('depth', 0)
        if self.arguments[0].startswith("lief._lief"):
            elements = self.arguments[0].split(".")[2:]
            cls = lief._lief
            for element in elements:
                cls = getattr(cls, element)
            self.arguments[0] = " ".join(self._check_module(lief, cls, depth))
        return super().run()

def setup(app):
    app.add_css_file('css/custom.css')  # may also be an URL

    app.add_role('commit', commit_role)
    app.add_role('pr', pr_role)
    app.add_role('issue', issue_role)
    app.add_role('github_user', github_user)
    app.add_role('xmark', xmark)
    app.add_role('fa-check', fa_check)
    app.add_directive('lief-inheritance', LIEFInheritanceDiagram)

    app.connect('autodoc-process-signature', _on_process_signature)
    app.connect('autodoc-process-docstring', _autodoc_process_docstring)

linkcheck_request_headers = {
    "*": {
        "Accept": "text/html,application/atom+xml",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:83.0) Gecko/20100101 Firefox/83.0",
    }
}
linkcheck_workers = 1
linkcheck_ignore = [
    'https://github.com',
    'http://github.com',
]

rst_prolog = """
.. |lief-extended-url| replace:: https://extended.lief.re/
.. |lief-rust-doc-nightly| replace:: https://lief-rs.s3.fr-par.scw.cloud/doc/latest/lief/index.html
"""


pygments_style = "xcode"
endpoint = "stable" if lief.__is_tagged__ else "latest"

html_theme_path = sphinx_lief.html_theme_path()
html_context    = sphinx_lief.get_html_context()
html_theme      = "sphinx_lief"
html_base_url   = "https://lief.re/"
base_url        = f"{html_base_url}/doc/{endpoint}"
html_theme_options = {
    "commit": commit,
    "base_url": f"{base_url}/",
    "sponsor_link": "https://github.com/sponsors/lief-project/",
    "repo_url": "https://github.com/lief-project/LIEF/",
    "repo_name": "LIEF",
    "html_minify": True,
    "html_prettify": False,
    "css_minify": True,
    "logo_icon": "logo_blue.png",
    "globaltoc_depth": 2,
    "color_primary": "blue",
    "color_accent": "cyan",
    "touch_icon": "favicon.ico",
    "nav_links": [
        {
            "href": html_base_url,
            "internal": False,
            "title": "Home",
            "icon": "fa-solid fa-house"
        },
        {
            "href": f"{html_base_url}/blog",
            "internal": False,
            "title": "Blog",
            "icon": "fa-solid fa-rss"
        },
        {
            "href": f"{html_base_url}/download",
            "internal": False,
            "title": "Download",
            "icon": "fa-solid fa-download",
        },
        {
            "href": "index",
            "internal": True,
            "title": "Documentation",
            "icon": "fa-solid fa-book",
            "subnav": [
                {
                    "title": "Doxygen",
                    "href": f"{base_url}/doxygen",
                },
            ]
        },
        {
            "href": f"{html_base_url}/about",
            "internal": False,
            "title": "About",
            "icon": "fa-solid fa-bars-staggered"
        },
    ],
    "table_classes": ["plain"],
}

html_last_updated_fmt = '%d/%m/%Y, %H:%M:%S'
html_logo        = '_static/logo_blue.png'
html_favicon     = '_static/favicon.ico'
html_static_path = ['_static']

htmlhelp_basename = 'LIEFdoc'
