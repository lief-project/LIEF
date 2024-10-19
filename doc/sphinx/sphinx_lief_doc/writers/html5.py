from docutils import nodes
from docutils.nodes import title

from sphinx.util import logging
from sphinx.writers.html5 import HTML5Translator as BaseHTML5Translator
from sphinx_lief_doc.lief_api import liefapi

logger = logging.getLogger(__name__)

class HTML5Translator(BaseHTML5Translator):
    def visit_paragraph(self, node: nodes.paragraph):
        # We can't have <div></div> element in a <p> scope
        # NOT ALLOWED:
        # <p>
        #   <div>hello</div>
        # </p>
        # Hence, if a liefapi node is within our children,
        # we need to replace with a <div> tag. The style of this <div> is
        # defined by the class fixed-paragraph located in custom.css
        if any(isinstance(e, liefapi) for e in node.children):
            node.get("classes", []).append("fixed-paragraph")
            self.body.append(self.starttag(node, 'div'))
        else:
            super().visit_paragraph(node)

    def depart_paragraph(self, node: nodes.paragraph):
        if 'fixed-paragraph' in node.get("classes", []):
            self.body.append("</div>")
        else:
            super().depart_paragraph(node)

    def visit_Text(self, node):
        if isinstance(node.parent, title):
            # Skip encoding
            self.body.append(node.astext())
            return
        super().visit_Text(node)
