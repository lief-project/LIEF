from typing import Iterator, Optional, Union as _Union

import lief.pdb


class Simple(lief.pdb.Type):
    pass

class Array(lief.pdb.Type):
    pass

class BitField(lief.pdb.Type):
    pass

class ClassLike(lief.pdb.Type):
    @property
    def attributes(self) -> Iterator[Optional[Attribute]]: ...

    @property
    def methods(self) -> Iterator[Optional[Method]]: ...

    @property
    def unique_name(self) -> str: ...

class Class(ClassLike):
    pass

class Structure(ClassLike):
    pass

class Interface(ClassLike):
    pass

class Attribute:
    @property
    def name(self) -> str: ...

    @property
    def type(self) -> Optional[lief.pdb.Type]: ...

    @property
    def field_offset(self) -> int: ...

class Method:
    @property
    def name(self) -> str: ...

class Enum(lief.pdb.Type):
    class Entry:
        @property
        def name(self) -> str: ...

        @property
        def value(self) -> int: ...

    @property
    def unique_name(self) -> str: ...

    @property
    def entries(self) -> list[Enum.Entry]: ...

    @property
    def underlying_type(self) -> lief.pdb.Type: ...

    def find_entry(self, value: int) -> Enum.Entry | None: ...

class Function(lief.pdb.Type):
    @property
    def return_type(self) -> Optional[lief.pdb.Type]: ...

    @property
    def parameters(self) -> list[Optional[lief.pdb.Type]]: ...

class Modifier(lief.pdb.Type):
    @property
    def underlying_type(self) -> Optional[lief.pdb.Type]: ...

class Pointer(lief.pdb.Type):
    @property
    def underlying_type(self) -> Optional[lief.pdb.Type]: ...

class Union(ClassLike):
    pass
