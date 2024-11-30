from typing import Iterator, Optional, Union

import lief


class Formal(lief.dwarf.Parameter):
    @property
    def type(self) -> Optional[lief.dwarf.Type]: ...

class TemplateType(lief.dwarf.Parameter):
    pass

class TemplateValue(lief.dwarf.Parameter):
    pass
