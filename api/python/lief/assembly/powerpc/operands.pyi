from typing import Optional, Union

import lief.assembly.powerpc

import lief.assembly.powerpc


class Immediate(lief.assembly.powerpc.Operand):
    __match_args__: tuple = ...

    @property
    def value(self) -> int: ...

class Register(lief.assembly.powerpc.Operand):
    __match_args__: tuple = ...

    @property
    def value(self) -> lief.assembly.powerpc.REG: ...

class Memory(lief.assembly.powerpc.Operand):
    __match_args__: tuple = ...

    @property
    def base(self) -> lief.assembly.powerpc.REG: ...

    @property
    def offset(self) -> Optional[Union[lief.assembly.powerpc.REG, int]]: ...

class PCRelative(lief.assembly.powerpc.Operand):
    __match_args__: tuple = ...

    @property
    def value(self) -> int: ...
