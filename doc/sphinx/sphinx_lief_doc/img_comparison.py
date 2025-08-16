from __future__ import annotations


from typing import TYPE_CHECKING
import shutil

from hashlib import md5

from pathlib import Path
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

def get_name(file: Path) -> str:
    return md5(bytes(file.absolute())).hexdigest() + file.name

class image_comparison(nodes.General, nodes.Element):
    def __init__(self, left: Path, right: Path, width: str | None):
        super().__init__()
        self.left = left
        self.right = right
        self.width = width

def visit_svg_files(self: HTML5Translator, node: Element):
    left = node.left.read_text()
    right = node.right.read_text()
    self.body.append(f"""
        <img-comparison-slider style="margin-bottom:6px;" class='img-comparison-slider-div'>
          <div slot="first">{left}</div>
          <div slot="second">{right}</div>
        </img-comparison-slider>
    """)

    raise nodes.SkipNode

def visit_image_comparison(self: HTML5Translator, node: Element):
    if node.left.name.endswith(".svg"):
        assert node.right.name.endswith(".svg")
        return visit_svg_files(self, node)
    images_dir = Path(self.builder.outdir / '_images')
    images_dir.mkdir(exist_ok=True)

    shutil.copy2(node.left, images_dir / get_name(node.left))
    shutil.copy2(node.right, images_dir / get_name(node.right))

    inline_style = ""
    if node.width is not None:
        inline_style = f'style="max-width:{node.width};"'

    self.body.append(f"""
        <img-comparison-slider {inline_style}>
          <img slot="first" src="{self.builder.imgpath}/{get_name(node.left)}" />
          <img slot="second" src="{self.builder.imgpath}/{get_name(node.right)}" />
        </img-comparison-slider>
    """)

    raise nodes.SkipNode

def depart_image_comparison(_: HTML5Translator, __: Element):
    pass

class ImageComparison(SphinxDirective):
    has_content = True
    required_arguments = 0
    optional_arguments = 2
    final_argument_whitespace = False

    option_spec: ClassVar[OptionSpec] = {
        'left': str,
        'right': str,
        'width': str,
    }

    def run(self) -> list[Node]:
        left_img = Path(self.options['left'])
        right_img = Path(self.options['right'])


        current_file, _ = self.get_source_info()
        current_file_dir = Path(current_file).parent

        assert (current_file_dir / left_img).is_file()
        assert (current_file_dir / right_img).is_file()

        node = image_comparison(
            current_file_dir / left_img,
            current_file_dir / right_img,
            self.options.get('width', None)
        )
        node.document = self.state.document
        return [node]

def setup(app: Sphinx):
    app.add_directive("img-comparison", ImageComparison)
    app.add_node(image_comparison, html=(visit_image_comparison, depart_image_comparison))
