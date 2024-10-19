from __future__ import annotations

from bs4 import BeautifulSoup
import re
from pathlib import Path
from copy import copy
from typing import TYPE_CHECKING, Any, Callable, Final, cast

from docutils import nodes
from docutils.nodes import Element, Node, system_message, reference
from docutils.parsers.rst import Directive
from docutils.statemachine import StringList

from sphinx import addnodes
from sphinx.addnodes import desc_signature, pending_xref
from sphinx.directives import ObjectDescription
from sphinx.domains import Domain, ObjType, TitleGetter
from sphinx.locale import _, __
from sphinx.roles import EmphasizedLiteral, XRefRole
from sphinx.util import docname_join, logging, ws_re
from sphinx.util.docutils import SphinxDirective
from sphinx.util.nodes import clean_astext, make_id, make_refnode

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from sphinx.application import Sphinx
    from sphinx.builders import Builder
    from sphinx.environment import BuildEnvironment
    from sphinx.util.typing import OptionSpec, RoleFunction

logger = logging.getLogger(__name__)

class RustXRef(XRefRole):
    def process_link(self, env, refnode, has_explicit_title, title, target):
        return title, target

class RustDomain(Domain):
    name = 'rust'
    label = "Rust"

    object_types: dict[str, ObjType] = {
        # ObjType(
        # lname: localized name of the type
        # roles: all the roles that can refer to an object of this type
        # attrs: object attributes
        'struct':   ObjType(_('struct'),   'struct'),
        'trait':    ObjType(_('trait'),    'trait'),
        'method':   ObjType(_('method'),   'method'),
        'module':   ObjType(_('module'),   'module'),
        'member':   ObjType(_('member'),   'member'),
        'enum':     ObjType(_('enum'),     'enum'),
        'function': ObjType(_('function'), 'func'),
    }

    directives: dict[str, Any] = {
    }

    roles = {
        'struct': RustXRef(),
        'trait':  RustXRef(),
        'method': RustXRef(),
        'module': RustXRef(),
        'member': RustXRef(),
        'enum':   RustXRef(),
        'func':   RustXRef(),
    }

    initial_data: dict[str, dict[str, tuple[Any]]] = {
        'objects': {},  # fullname -> docname, objtype
    }

    def clear_doc(self, docname: str) -> None:
        return

    def process_doc(self, env: BuildEnvironment, docname: str,
                    document: nodes.document) -> None:
        return

    def process_field_xref(self, pnode: pending_xref) -> None:
        return

    def merge_domaindata(self, docnames: list[str], otherdata: dict[str, Any]) -> None:
        return

    def gen_url(self, env: BuildEnvironment, target: str, url: str) -> str | None:
        config = env.config
        if config.lief_rust_doc_check is not None:
            path: Path = config.lief_rust_doc_check / url
            target_name = path.name

            if '#' in target_name:
                filename, anchor = target_name.split('#')
                normalized = path.parent / filename
                if not normalized.exists():
                    logger.warning("Path %s for %s does not exist", url, target)
                    return None
                html = normalized.read_text()
                soup = BeautifulSoup(html, 'html.parser')
                if soup.find(id=anchor) is None:
                    logger.warning("Missing reference: %s in %s for %s", anchor, normalized, target)
                    return None

            elif not path.exists():
                logger.warning("Path %s for %s does not exist", url, target)
                return None

        url_domain = config.lief_rust_doc_base_url if config.lief_is_release else \
                     config.lief_rust_doc_nightly_base_url

        return f"{url_domain}/{url}"

    def _find_struct(self, env: BuildEnvironment, target: str) -> str | None:
        parts = target.split('::')
        prefix = "/".join(parts[:-1])
        suffix = f"struct.{parts[-1]}.html"

        return self.gen_url(env, target, f"{prefix}/{suffix}")

    def _find_module(self, env: BuildEnvironment, target: str) -> str | None:
        parts = target.split('::')
        prefix = "/".join(parts)
        suffix = "index.html"

        return self.gen_url(env, target, f"{prefix}/{suffix}")

    def _find_trait(self, env: BuildEnvironment, target: str) -> str | None:
        """
        e.g. :rust:trait:`lief::generic::Symbol`
        """
        parts = target.split('::')
        prefix = "/".join(parts[:-1])
        suffix = f"trait.{parts[-1]}.html"

        return self.gen_url(env, target, f"{prefix}/{suffix}")

    def _find_method(self, env: BuildEnvironment, target: str) -> str | None:
        """
        e.g. :rust:method:`lief::Relocation::address [trait]`
        """
        ref, spec = target.split(' ')
        spec = spec.replace("[", "").replace("]", "")

        parts = ref.split('::')
        prefix = "/".join(parts[:-2])
        suffix = f"{spec}.{parts[-2]}.html#method.{parts[-1]}"

        return self.gen_url(env, target, f"{prefix}/{suffix}")

    def _find_member(self, env: BuildEnvironment, target: str) -> str | None:
        """
        e.g. :rust:member:`lief::Range::low [struct]`
        """
        ref, spec = target.split(' ')
        spec = spec.replace("[", "").replace("]", "")

        parts = ref.split('::')
        prefix = "/".join(parts[:-2])
        suffix = f"{spec}.{parts[-2]}.html#structfield.{parts[-1]}"

        return self.gen_url(env, target, f"{prefix}/{suffix}")

    def _find_enum(self, env: BuildEnvironment, target: str) -> str | None:
        """
        e.g. :rust:enum:`lief::elf::header::Class`
        """
        parts = target.split('::')
        prefix = "/".join(parts[:-1])
        suffix = f"enum.{parts[-1]}.html"

        return self.gen_url(env, target, f"{prefix}/{suffix}")

    def _find_func(self, env: BuildEnvironment, target: str) -> str | None:
        """
        e.g. :rust:func:`lief::is_extended`
        """
        parts = target.split('::')
        prefix = "/".join(parts[:-1])
        suffix = f"fn.{parts[-1]}.html"

        return self.gen_url(env, target, f"{prefix}/{suffix}")

    def _resolve_xref_impl(self, env: BuildEnvironment,
                           typ: str, target: str) -> str | None:
        if typ == "struct":
            return self._find_struct(env, target)

        if typ == "module":
            return self._find_module(env, target)

        if typ == "trait":
            return self._find_trait(env, target)

        if typ == "method":
            return self._find_method(env, target)

        if typ == "member":
            return self._find_member(env, target)

        if typ == "enum":
            return self._find_enum(env, target)

        if typ == "func":
            return self._find_func(env, target)

        logger.warning("Can't compute xref for: %s (%s)", target, typ)
        return None

    def resolve_xref(self, env: BuildEnvironment, fromdocname: str, builder: Builder,
                     typ: str, target: str, node: pending_xref,
                     contnode: Element) -> Element | None:
        refuri = self._resolve_xref_impl(env, typ, target)
        # strip the [<info>] from the text
        text_node: nodes.Text = contnode.children[0]
        contnode.children = [
            nodes.Text(text_node.split(' ')[0])
        ]

        if refuri is None:
            node = reference("", "", refuri="#")
            node += contnode
            return node

        node = reference("", "", refuri=refuri)
        node += contnode
        return node

    def resolve_any_xref(self, env: BuildEnvironment, fromdocname: str, builder: Builder,
                         target: str, node: pending_xref, contnode: Element,
                         ) -> list[tuple[str, Element]]:
        raise NotImplementedError()

    def get_objects(self) -> Iterator[tuple[str, str, str, str, str, int]]:
        return
        yield
