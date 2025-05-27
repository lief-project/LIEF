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

class lief_sdk_package(nodes.General, nodes.Element):
    def __init__(self, title: str, s3_prefix: str, files: list[dict]):
        super().__init__()
        self.s3_prefix = s3_prefix
        self.files = files
        self.title = title

def visit_lief_sdk_package(self: HTML5Translator, node: Element):
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
            <i class="fa-solid fa-download">&nbsp;</i>{node.title}
        </span>
    </p>
    <ul>
    {html_files}
    </ul>
    </div>
    """)

    raise nodes.SkipNode

def depart_lief_sdk_package(_: HTML5Translator, __: Element):
    pass

def _normalize(string: str) -> str:
    string = string.lower()
    string = string.strip()
    return string

def list_str(argument: str) -> list[str] | None:
    if argument is None:
        return None

    values = argument.split(',')
    return [_normalize(s) for s in values]

class SdkPackage(SphinxDirective):
    has_content = True
    required_arguments = 1
    optional_arguments = 2
    final_argument_whitespace = False

    option_spec: ClassVar[OptionSpec] = {
        'file': str,
        'filter': list_str,
    }

    def run(self) -> list[Node]:
        config = self.env.config

        sdk_filter = self.options['filter']
        title = self.arguments[0]

        index_file = f"{config.lief_s3_url_prefix}/{self.options['file']}"
        logger.info("Indexing sdk based on %s (filter: %s)", index_file, sdk_filter)

        content = requests.get(index_file, timeout=5).json()
        logger.info("Filters: %s", sdk_filter)
        if sdk_filter is None or len(sdk_filter) == 0:
            node = lief_sdk_package(title, config.lief_s3_url_prefix, content)
        else:
            filtered_files = []
            for file in content:
                if any(s in file['name'].lower() for s in sdk_filter):
                    filtered_files.append(file)
            node = lief_sdk_package(title, config.lief_s3_url_prefix, filtered_files)

        node.document = self.state.document
        return [node]

def setup(app: Sphinx):
    app.add_directive("sdk-package", SdkPackage)
    app.add_node(lief_sdk_package, html=(visit_lief_sdk_package, depart_lief_sdk_package))
