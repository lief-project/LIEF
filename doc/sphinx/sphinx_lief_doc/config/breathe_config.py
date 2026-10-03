import lief
import os
import re
import sphinx_lief

from breathe.renderer.sphinxrenderer import SphinxRenderer
from pathlib import Path
from sphinx.application import Sphinx

CURRENT_DIR = Path(__file__).parent
LIEF_ROOT_DIR = (CURRENT_DIR / "../../../..").resolve().absolute()

DOXYGEN_XML_PATH = Path(os.environ['LIEF_DOXYGEN_XML']).resolve().absolute()

assert DOXYGEN_XML_PATH.exists()

DOXYGEN_ANONYMOUS_RE = re.compile(r"^\[(?:class|struct|union)\]\.__unnamed(\d+)__$")

_join_nested_name = SphinxRenderer.join_nested_name

def join_nested_name(self: SphinxRenderer, names: list[str]) -> str:
    names = [DOXYGEN_ANONYMOUS_RE.sub(r"@unnamed\1", name) for name in names]
    return _join_nested_name(self, names)

def setup(app: Sphinx):
    SphinxRenderer.join_nested_name = join_nested_name

    app.config.breathe_default_members = ('members', 'protected-members', 'undoc-members')
    app.config.breathe_show_enumvalue_initializer = True

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
    app.config.breathe_projects = {
        "lief": DOXYGEN_XML_PATH,
    }

    app.config.breathe_domain_by_extension = {
        "h" : "c",
        "hpp" : "cpp",
    }

    app.config.breathe_doxygen_config_options = {
        "WARN_IF_UNDOCUMENTED": "NO",
        "MACRO_EXPANSION": "YES",
        'PREDEFINED': " ".join(PREDEFINED),
        'EXPAND_AS_DEFINED': " ".join(EXPAND_AS_DEFINED)
    }

    app.config.breathe_default_project = "lief"
