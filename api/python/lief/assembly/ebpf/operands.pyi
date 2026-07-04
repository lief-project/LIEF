from typing import Iterator, Optional, Union

import lief.assembly.ebpf


class Immediate(lief.assembly.ebpf.Operand):
    @property
    def value(self) -> int: ...

class Register(lief.assembly.ebpf.Operand):
    @property
    def value(self) -> lief.assembly.ebpf.REG: ...

class Memory(lief.assembly.ebpf.Operand):
    @property
    def base(self) -> lief.assembly.ebpf.REG: ...

    @property
    def displacement(self) -> int: ...

class PCRelative(lief.assembly.ebpf.Operand):
    @property
    def value(self) -> int: ...
