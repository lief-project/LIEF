from typing import Iterator, Optional, Union

import lief


class Immediate(lief.assembly.x86.Operand):
    @property
    def value(self) -> int: ...

class Memory(lief.assembly.x86.Operand):
    @property
    def base(self) -> lief.assembly.x86.REG: ...

    @property
    def scaled_register(self) -> lief.assembly.x86.REG: ...

    @property
    def segment_register(self) -> lief.assembly.x86.REG: ...

    @property
    def scale(self) -> int: ...

    @property
    def displacement(self) -> int: ...

class PCRelative(lief.assembly.x86.Operand):
    @property
    def value(self) -> int: ...

class Register(lief.assembly.x86.Operand):
    @property
    def value(self) -> lief.assembly.x86.REG: ...
