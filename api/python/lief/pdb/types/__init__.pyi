from typing import Iterator, Optional, Union as _Union

import lief


class Array(lief.pdb.Type):
    pass

class Attribute:
    @property
    def name(self) -> str: ...

    @property
    def type(self) -> Optional[lief.pdb.Type]: ...

    @property
    def field_offset(self) -> int: ...

class BitField(lief.pdb.Type):
    pass

class Class(ClassLike):
    pass

class ClassLike(lief.pdb.Type):
    @property
    def attributes(self) -> Iterator[Optional[Attribute]]: ...

    @property
    def methods(self) -> Iterator[Optional[Method]]: ...

    @property
    def unique_name(self) -> str: ...

    @property
    def name(self) -> str: ...

    @property
    def size(self) -> int: ...

class Enum(lief.pdb.Type):
    pass

class Function(lief.pdb.Type):
    pass

class Interface(ClassLike):
    pass

class Method:
    @property
    def name(self) -> str: ...

class Modifier(lief.pdb.Type):
    @property
    def underlying_type(self) -> Optional[lief.pdb.Type]: ...

class Pointer(lief.pdb.Type):
    @property
    def underlying_type(self) -> Optional[lief.pdb.Type]: ...

class Simple(lief.pdb.Type):
    pass

class Structure(ClassLike):
    pass

class Union(ClassLike):
    pass
