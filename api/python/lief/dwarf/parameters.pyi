from typing import Optional

import lief.dwarf


class Formal(lief.dwarf.Parameter):
    @property
    def type(self) -> Optional[lief.dwarf.Type]: ...

class TemplateValue(lief.dwarf.Parameter):
    pass

class TemplateType(lief.dwarf.Parameter):
    pass
