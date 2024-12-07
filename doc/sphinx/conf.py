#!/usr/bin/env python

import sys
from pathlib import Path
sys.path.insert(0, Path(__file__).parent.as_posix())

from sphinx_lief_doc.writers.html5 import HTML5Translator
from sphinx_lief_doc.rust_domain import RustDomain
from sphinx_lief_doc.roles import setup as setup_roles
from sphinx_lief_doc.inheritance_diagram import LIEFInheritanceDiagram
from sphinx_lief_doc.python_typing import setup as setup_python_typing
from sphinx_lief_doc.config import init_config as lief_init_config
from sphinx_lief_doc.lief_api import setup as setup_lief_api

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sphinx.application import Sphinx

extensions = [
    'sphinx.ext.mathjax',
    'sphinx.ext.autodoc',
    'sphinx.ext.extlinks',
    "sphinx_tabs.tabs",
    'sphinx.ext.inheritance_diagram',
    'breathe', 'sphinx_lief'
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']
source_suffix = {'.rst': 'restructuredtext'}

extlinks = {
    'github-ref': ("https://github.com/%s", "%s"),
    'llvm-pr': ("https://github.com/llvm/llvm-project/pull/%s", "llvm/llvm-project#%s"),
}

# Can be used for debugging breathe
#breathe_debug_trace_directives = True
#breathe_debug_trace_doxygen_ids = True
#breathe_debug_trace_qualification = True

master_doc = 'index'

project    = 'LIEF'
html_title = "LIEF Documentation"
copyright  = '2020, Quarkslab'
author     = 'Romain Thomas'

language = "en"
autoclass_content = 'both'
autodoc_default_options = {
    'exclude-members': '@entries',
    'undoc-members': True,
    'inherited-members': False,
    'show-inheritance': False,
    'members': True,
}

exclude_patterns = [
#    "tutorials/*.rst",
#    "extended/*.rst",
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
]


def setup(app: Sphinx):
    lief_init_config(app)

    app.add_css_file('css/custom.css')  # may also be an URL
    app.add_domain(RustDomain)

    setup_python_typing(app)
    setup_roles(app)
    setup_lief_api(app)

    app.add_directive('lief-inheritance', LIEFInheritanceDiagram)
    app.set_translator('html', HTML5Translator)
