import lief
import os
import sphinx_lief

from pathlib import Path
from sphinx.application import Sphinx

CURRENT_DIR = Path(__file__).parent
LIEF_ROOT_DIR = (CURRENT_DIR / "../../../..").resolve().absolute()

DOXYGEN_XML_PATH = Path(os.environ['LIEF_DOXYGEN_XML']).resolve().absolute()

assert DOXYGEN_XML_PATH.exists()

def setup(app: Sphinx):
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
