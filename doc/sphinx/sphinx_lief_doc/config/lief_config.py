import lief
import os
from typing import Any
from pathlib import Path

from docutils import nodes
from sphinx.application import Sphinx
from sphinx.transforms import SphinxTransform
from sphinx.util import logging

logger = logging.getLogger(__name__)

_LIEF_VERSION_ENV_KEY  = "LIEF_VERSION"
_LIEF_RUST_DOC_ENV_KEY = "LIEF_RUST_DOC_CHECK_PATH"
_LIEF_RELEASE_ENV_KEY  = "LIEF_DOC_IS_RELEASE"

class Substitutions(SphinxTransform):
    default_priority = 210

    def apply(self, **kwargs: Any) -> None:
        for ref in self.document.findall(nodes.substitution_reference):
            refname = ref['refname']
            text = None
            if refname == 'lief-extended-url':
                text = self.config.lief_extended_url
            elif refname == 'lief-rust-doc-nightly':
                text = self.config.lief_rust_doc_nightly
            elif refname == 'lief-rust-doc':
                text = self.config.lief_rust_doc
            elif refname == 'lief-extended-email':
                text = self.config.lief_extended_email
            elif refname == 'lief-llvm-version':
                text = self.config.lief_llvm_version

            if text is None:
                continue

            if text.startswith("http://") or text.startswith("https://"):
                ref.replace_self(nodes.reference(text, text, refuri=text))
            else:
                ref.replace_self(nodes.Text(text))

def get_version() -> str:
    return os.getenv(_LIEF_VERSION_ENV_KEY) or (
        lief.__tag__ if lief.__is_tagged__ else lief.__version__
    )

def get_release() -> str:
    return os.getenv(_LIEF_VERSION_ENV_KEY) or lief.__version__

def get_rust_doc_check() -> Path | None:
    value = os.getenv(_LIEF_RUST_DOC_ENV_KEY)
    if value is not None:
        return Path(value).resolve().absolute()
    return None

def setup(app: Sphinx):
    app.config.version = get_version()
    app.config.release = get_release()

    app.config.lief_is_release = lief.__is_tagged__ or \
                                 os.getenv(_LIEF_RELEASE_ENV_KEY) is not None

    app.config.lief_commit = lief.__commit__
    app.config.lief_public_website = "https://lief.re"
    app.config.lief_html_theme = "sphinx_lief"
    app.config.lief_doc_endpoint = "stable" if app.config.lief_is_release else "latest"
    app.config.lief_gh_repo = "LIEF"
    app.config.lief_gh_org = "lief-project"
    app.config.lief_discord = "https://discord.gg/jGQtyAYChJ"
    app.config.lief_gh_repo_url = "https://github.com/lief-project/LIEF"
    app.config.lief_gh_sponsor_url = "https://github.com/sponsors/lief-project"
    app.config.lief_extended_url = "https://extended.lief.re/"
    app.config.lief_extended_email = "extended@lief.re"
    app.config.lief_llvm_version = "19.1.2"

    app.config.lief_rust_doc_base_url = "https://lief.re/doc/stable/rust"
    app.config.lief_rust_doc = f"{app.config.lief_rust_doc_base_url}/lief"

    app.config.lief_rust_doc_nightly_base_url = "https://lief-rs.s3.fr-par.scw.cloud/doc/latest"
    app.config.lief_rust_doc_nightly = f"{app.config.lief_rust_doc_nightly_base_url}/lief/index.html"

    app.config.lief_rust_doc_check = get_rust_doc_check()

    app.add_transform(Substitutions)
