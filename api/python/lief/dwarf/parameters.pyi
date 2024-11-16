from typing import Optional

import lief.dwarf # type: ignore

class Formal(lief.dwarf.Parameter):
    def __init__(self, *args, **kwargs) -> None: ...
    @property
    def type(self) -> Optional[lief.dwarf.Type]: ...

class TemplateType(lief.dwarf.Parameter):
    def __init__(self, *args, **kwargs) -> None: ...

class TemplateValue(lief.dwarf.Parameter):
    def __init__(self, *args, **kwargs) -> None: ...
