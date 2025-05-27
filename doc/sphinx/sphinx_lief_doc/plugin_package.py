from __future__ import annotations

import requests

from typing import TYPE_CHECKING

from sphinx.directives import SphinxDirective
from sphinx.util import logging
from sphinx.application import Sphinx

from sphinx.writers.html import HTML5Translator

from docutils import nodes
from docutils.nodes import Element, Node

if TYPE_CHECKING:
    from typing import ClassVar

    from sphinx.application import Sphinx
    from sphinx.util.typing import OptionSpec

logger = logging.getLogger(__name__)

class lief_package(nodes.General, nodes.Element):
    def __init__(self, s3_prefix: str, kind: str, files: list[dict]):
        super().__init__()
        self.s3_prefix = s3_prefix
        self.kind = kind
        self.files = files

def visit_lief_package(self: HTML5Translator, node: Element):
    html_files = ""
    for file in node.files:
        html_files += f"""
        <li class="toctree-l1">
        <a class="reference internal" href="{node.s3_prefix}/{file['path']}">
        <em class="fa fa-solid fa-file-zipper">&nbsp;</em>{file['name']}</a>
        </li>
        """

    self.body.append(f"""
    <div class="toctree-wrapper compound">
    <p class="caption" role="heading">
        <span class="caption-text">
            <i class="fa-solid fa-download">&nbsp;</i>Downloads
        </span>
    </p>
    <ul>
    {html_files}
    </ul>
    </div>
    """)

    raise nodes.SkipNode

def depart_lief_package(_: HTML5Translator, __: Element):
    pass

class PluginPackage(SphinxDirective):
    has_content = True
    required_arguments = 1
    optional_arguments = 0
    final_argument_whitespace = False

    option_spec: ClassVar[OptionSpec] = {
        'file': str,
    }

    def run(self) -> list[Node]:
        config = self.env.config

        name = self.arguments[0]

        index_file = f"{config.lief_s3_url_prefix}/{self.options['file']}"
        logger.info("Indexing %s based on %s", name, index_file)
        content = requests.get(index_file, timeout=5).json()

        node = lief_package(config.lief_s3_url_prefix, name, content[name])
        node.document = self.state.document
        return [node]

def setup(app: Sphinx):
    app.add_directive("plugin-package", PluginPackage)
    app.add_node(lief_package, html=(visit_lief_package, depart_lief_package))
