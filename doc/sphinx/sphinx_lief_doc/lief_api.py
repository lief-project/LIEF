import re

from docutils import nodes
from docutils.nodes import Element, Node
from sphinx.application import Sphinx
from sphinx.directives import SphinxDirective
from sphinx.util import logging
from sphinx.writers.html import HTML5Translator

logger = logging.getLogger(__name__)


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", name.casefold()).strip("-")


class liefapi_name(nodes.TextElement, nodes.Inline):
    pass


def visit_liefapi_name_node(self: HTML5Translator, node: Element):
    base_id = node["lief-api-id"]
    counts = getattr(self, "_lief_api_id_counts", {})
    count = counts.get(base_id, 0) + 1
    counts[base_id] = count
    self._lief_api_id_counts = counts

    string_id = base_id if count == 1 else f"{base_id}-{count}"
    for sibling in node.parent.children:
        sibling["lief-api-rendered-id"] = string_id

    self.body.append(
        f"""
        <a href="#" role="button" id="{string_id}" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
    """
    )
    self.body.append(
        f'<code><span class="pre">{self.encode(node.astext())}</span></code>'
    )
    self.body.append("</a>")


def depart_liefapi_name_node(self, node: Element):
    pass


class liefapi_elements(nodes.General, nodes.Element, nodes.Inline):
    pass


def visit_custom_literal(self: HTML5Translator, node: nodes.literal):
    text = self.encode(node.children[0].astext())
    icon = ""
    if "rust" in node["classes"]:
        icon = '<i class="fa fa-brands fa-rust"></i> '
    elif "py" in node["classes"]:
        icon = '<i class="fa fa-brands fa-python"></i> '
    elif "cpp" in node["classes"]:
        icon = '<i class="fa fa-regular fa-file-code"></i> '

    self.body.append(
        """
        <code class="{classes}"><span class="pre">{icon}{text}</span></code>
    """.format(classes=" ".join(node["classes"]), text=text, icon=icon)
    )


def visit_liefapi_elements_node(self: HTML5Translator, node: Element):
    self.body.append(
        '<div class="dropdown-menu" aria-labelledby="{}">'.format(
            node.get("lief-api-rendered-id", node["lief-api-id"])
        )
    )
    paragraph = node.children[0]
    for element in paragraph:
        if (
            isinstance(element, nodes.Text)
            and element.astext().replace("\n", "").strip() == ""
        ):
            # logger.warning("skip children empty Text node")
            continue

        item = '<a class="dropdown-item"'
        if isinstance(element, nodes.reference):
            item += ' href="{}"'.format(element["refuri"])
        else:
            item += ' href="#"'
        item += ">"
        self.body.append(item)

        literal_node = element
        if isinstance(element, nodes.reference):
            literal_node = element.children[0]

        assert isinstance(literal_node, nodes.literal)

        visit_custom_literal(self, literal_node)
        self.body.append("</a>")

    self.body.append("</div>")


def depart_liefapi_elements_node(self, node: Element):
    pass


class liefapi(nodes.General, nodes.Element, nodes.Inline):
    pass


def visit_liefapi_node(self: HTML5Translator, node: Element):
    self.body.append(
        self.starttag(node, "div", classes=["dropdown"], style="display:inline;")
    )
    for element in node.children:
        if isinstance(element, liefapi_name):
            visit_liefapi_name_node(self, element)

        if isinstance(element, liefapi_elements):
            visit_liefapi_elements_node(self, element)

    self.body.append("</div>")
    raise nodes.SkipNode


def depart_liefapi_node(self: HTML5Translator, node: Element):
    pass


class LIEFApi(SphinxDirective):
    has_content = True
    required_arguments = 1
    optional_arguments = 0
    final_argument_whitespace = False

    def run(self) -> list[Node]:
        if len(self.arguments) != 1:
            raise RuntimeError("Missing argument for lief-api")

        node = liefapi()
        node.document = self.state.document

        name = self.arguments[0]
        identifier = f"lief-api-{_slugify(name)}-{self.env.new_serialno('lief-api')}"
        name_node = liefapi_name(text=name)
        name_node["lief-api-id"] = identifier
        node += name_node

        elements = liefapi_elements()
        elements.document = self.state.document
        elements["lief-api-id"] = identifier
        self.state.nested_parse(self.content, self.content_offset, elements)

        node += elements
        return [node]


def setup(app: Sphinx):
    app.add_directive("lief-api", LIEFApi)
    app.add_node(liefapi, html=(visit_liefapi_node, depart_liefapi_node))

    app.add_node(liefapi_name, html=(visit_liefapi_name_node, depart_liefapi_name_node))

    app.add_node(
        liefapi_elements,
        html=(visit_liefapi_elements_node, depart_liefapi_elements_node),
    )
