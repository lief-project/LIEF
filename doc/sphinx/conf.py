#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import re
import lief
import os
import pathlib
from docutils import nodes
import inspect
from sphinx.util import logging
from sphinx.util.inspect import (
    evaluate_signature,
    getdoc,
    object_description,
    safe_getattr,
    stringify_signature,
    signature_from_str
)

RE_INST = re.compile(r"\s=\s<.*\sobject\sat[^>]*>")

GENERATE_DOXYGEN = False
DOXYGEN_XML_PATH = None
USE_RTD_THEME = False

try:
    import sphinx_lief
except Exception:
    import sphinx_rtd_theme
    USE_RTD_THEME = True


try:
    import breathe
    DOXYGEN_XML_PATH = os.getenv("LIEF_DOXYGEN_XML", None)
    if DOXYGEN_XML_PATH is not None and pathlib.Path(DOXYGEN_XML_PATH).exists():
        DOXYGEN_XML_PATH = pathlib.Path(DOXYGEN_XML_PATH).resolve().absolute()
        GENERATE_DOXYGEN = True
except Exception:
    GENERATE_DOXYGEN = False


FORCE_RTD_THEME = os.environ.get("FORCE_RTD_THEME", False)
FORCE_RTD_THEME = FORCE_RTD_THEME in ("1", "true", "yes")

if FORCE_RTD_THEME:
    import sphinx_rtd_theme

USE_RTD_THEME = USE_RTD_THEME or FORCE_RTD_THEME

extensions = [
    'sphinx.ext.mathjax',
    'sphinx.ext.autodoc',
]

if GENERATE_DOXYGEN:
    extensions += ["breathe"]
    breathe_projects = {
        "lief": DOXYGEN_XML_PATH,
    }

logger = logging.getLogger("lief-doc")
# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

source_suffix = '.rst'

master_doc = 'index'

project    = 'LIEF'
html_title = "LIEF Documentation"
copyright  = '2020, Quarkslab'
author     = 'Romain Thomas'

version = lief.__tag__ if lief.__is_tagged__ else lief.__version__
release = lief.__version__
commit  = lief.__commit__

language = "en"
autoclass_content = 'both'
autodoc_default_options = {
    'exclude-members': '@entries'
}

if GENERATE_DOXYGEN:
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
    commit_link = nodes.reference(
            "", text[:7], refuri="https://github.com/lief-project/LIEF/commit/{}".format(text), **options)

    return [commit_link], []

def pr_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    pr_link = nodes.reference(
            "", '#' + text, refuri="https://github.com/lief-project/LIEF/pull/{}".format(text), **options)

    return [pr_link], []

def issue_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
    issue_link = nodes.reference(
            "", '#' + text, refuri="https://github.com/lief-project/LIEF/issues/{}".format(text), **options)

    return [issue_link], []

def github_user(name, rawtext, text, lineno, inliner, options={}, content=[]):
    issue_link = nodes.reference(
            "", text, refuri="https://github.com/{}".format(text), **options)

    return [issue_link], []

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
        logger.warn(f"Error with {name}: {lines[0]}")

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


def setup(app):
    app.add_css_file('css/custom.css')  # may also be an URL

    app.add_role('commit', commit_role)
    app.add_role('pr', pr_role)
    app.add_role('issue', issue_role)
    app.add_role('github_user', github_user)

    app.connect('autodoc-process-signature', _on_process_signature)

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


if not USE_RTD_THEME:
    pygments_style = "xcode"
    endpoint = "stable" if lief.__is_tagged__ else "latest"
    extensions.append("sphinx_lief")
    html_theme_path = sphinx_lief.html_theme_path()
    html_context    = sphinx_lief.get_html_context()
    html_theme      = "sphinx_lief"
    html_base_url   = "https://lief-project.github.io/"
    base_url        = f"{html_base_url}/doc/{endpoint}"
    html_theme_options = {
        "commit": commit,
        "base_url": f"{base_url}/",
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
                "title": "Home"
            },
            {
                "href": f"{html_base_url}/blog",
                "internal": False,
                "title": "Blog"
            },
            {
                "href": f"{html_base_url}/download",
                "internal": False,
                "title": "Download"
            },
            {
                "href": "index",
                "internal": True,
                "title": "Documentation",
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
            },
        ],
        "table_classes": ["plain"],
    }
else:
    html_theme = "sphinx_rtd_theme"
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

html_last_updated_fmt = '%d/%m/%Y, %H:%M:%S'
html_logo        = '_static/logo_blue.png'
html_favicon     = '_static/favicon.ico'
html_static_path = ['_static']

htmlhelp_basename = 'LIEFdoc'

