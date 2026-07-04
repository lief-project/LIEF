import lief.assembly.mips
from typing import Iterator, Optional, Union

import lief.assembly.mips


class Immediate(lief.assembly.mips.Operand):
    @property
    def value(self) -> int: ...

class Register(lief.assembly.mips.Operand):
    @property
    def value(self) -> lief.assembly.mips.REG: ...

class Memory(lief.assembly.mips.Operand):
    @property
    def base(self) -> lief.assembly.mips.REG: ...

    @property
    def offset(self) -> Optional[Union[lief.assembly.mips.REG, int]]: ...

class PCRelative(lief.assembly.mips.Operand):
    @property
    def value(self) -> int: ...
