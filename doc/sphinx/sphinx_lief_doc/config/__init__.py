import lief
import sphinx_lief

from sphinx.application import Sphinx
from sphinx_lief_doc.config.breathe_config import setup as setup_breathe
from sphinx_lief_doc.config.lief_config import setup as setup_lief
from sphinx_lief_doc.config.html_config import setup as setup_html
from sphinx_lief_doc.config.link_check import setup as setup_link_check

def init_config(app: Sphinx):
    app.config.pygments_style = "xcode"

    setup_lief(app)
    setup_html(app)
    setup_breathe(app)
    setup_link_check(app)
