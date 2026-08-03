import sys
from pathlib import Path

sys.path.insert(0, Path(__file__).parent.as_posix())

from sphinx.application import Sphinx
from sphinx_lief_doc.config import init_config as lief_init_config
from sphinx_lief_doc.img_comparison import setup as setup_img_comparison
from sphinx_lief_doc.inheritance_diagram import LIEFInheritanceDiagram
from sphinx_lief_doc.lief_api import setup as setup_lief_api
from sphinx_lief_doc.literalinclude import LiteralInclude
from sphinx_lief_doc.plugin_package import setup as setup_plugin_packages
from sphinx_lief_doc.python_typing import setup as setup_python_typing
from sphinx_lief_doc.roles import setup as setup_roles
from sphinx_lief_doc.rust_domain import RustDomain
from sphinx_lief_doc.sdk_package import setup as setup_sdk_packages
from sphinx_lief_doc.seo import setup as setup_seo
from sphinx_lief_doc.writers.html5 import HTML5Translator

extensions = [
    "myst_parser",
    "sphinx.ext.mathjax",
    "sphinx.ext.autodoc",
    "sphinx.ext.extlinks",
    "sphinx_tabs.tabs",
    "sphinx.ext.inheritance_diagram",
    "breathe",
    "sphinx_lief",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]
source_suffix = {".md": "markdown"}
exclude_patterns = ["_cross_api.md"]

myst_enable_extensions = [
    "colon_fence",
    "substitution",
]
myst_all_links_external = True
myst_footnote_sort = False
myst_substitutions = {
    "cross_api": "```{include} /_cross_api.md\n```",
    "literalinclude": LiteralInclude(),
}

extlinks = {
    "github-ref": ("https://github.com/%s", "%s"),
    "llvm-pr": ("https://github.com/llvm/llvm-project/pull/%s", "llvm/llvm-project#%s"),
}

# Can be used for debugging breathe
# breathe_debug_trace_directives = True
# breathe_debug_trace_doxygen_ids = True
# breathe_debug_trace_qualification = True

master_doc = "index"

suppress_warnings = ["config.cache"]

project = "LIEF"
html_title = "LIEF Documentation"
copyright = "2020, Quarkslab"
author = "Romain Thomas"

language = "en"
autoclass_content = "both"
autodoc_default_options = {
    "exclude-members": "@entries",
    "undoc-members": True,
    "inherited-members": False,
    "show-inheritance": False,
    "members": True,
}

# exclude_patterns = [
#    "api",
#    "tutorials/*.md",
#    "changelog/*.md",
#    "extended",
#    "formats",
#    "changelog.md",
#    "references.md",
#    "intro.md",
#    "installation.md",
#    "compilation.md",
# ]


def setup(app: Sphinx):
    lief_init_config(app)

    app.add_css_file("css/custom.css")  # may also be an URL
    app.add_domain(RustDomain)

    setup_python_typing(app)
    setup_roles(app)
    setup_lief_api(app)
    setup_img_comparison(app)
    setup_plugin_packages(app)
    setup_sdk_packages(app)
    setup_seo(app)

    app.add_directive("lief-inheritance", LIEFInheritanceDiagram)
    app.set_translator("html", HTML5Translator)
