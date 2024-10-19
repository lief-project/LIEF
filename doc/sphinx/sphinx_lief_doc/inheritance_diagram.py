import inspect
import lief
from sphinx.ext.inheritance_diagram import InheritanceDiagram
from sphinx.util.typing import OptionSpec
from docutils.nodes import Node

class LIEFInheritanceDiagram(InheritanceDiagram):
    option_spec: OptionSpec = {
        **InheritanceDiagram.option_spec,
        'depth': int
    }
    def _check_module(self, module, obj, depth: int):
        if not module.__name__.startswith("lief"):
            return []

        classes = []
        for name, member in inspect.getmembers(module):
            if inspect.isclass(member) and issubclass(member, obj):
                mro = inspect.getmro(member)
                if (0 < depth and mro.index(obj) <= depth) or depth == 0:
                    classes.append(f"{module.__name__}.{name}")
            if inspect.ismodule(member) and member != module:
                classes.extend(self._check_module(member, obj, depth))
        return list(set(classes))

    def run(self) -> list[Node]:
        cls = None
        depth = self.options.get('depth', 0)
        if self.arguments[0].startswith("lief._lief"):
            elements = self.arguments[0].split(".")[2:]
            cls = lief._lief
            for element in elements:
                cls = getattr(cls, element)
            self.arguments[0] = " ".join(self._check_module(lief, cls, depth))
        return super().run()
