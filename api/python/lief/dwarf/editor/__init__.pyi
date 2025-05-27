from collections.abc import Sequence
import enum
from typing import Iterator, Optional, Union, overload


class Type:
    def pointer_to(self) -> Optional[PointerType]: ...

class PointerType(Type):
    pass

class EnumType(Type):
    class Value:
        pass

    def set_size(self, size: int) -> EnumType: ...

    def add_value(self, name: str, value: int) -> Optional[EnumType.Value]: ...

class BaseType(Type):
    class ENCODING(enum.Enum):
        NONE = 0

        ADDRESS = 1

        SIGNED = 2

        SIGNED_CHAR = 3

        UNSIGNED = 4

        UNSIGNED_CHAR = 5

        BOOLEAN = 6

        FLOAT = 7

class ArrayType(Type):
    pass

class FunctionType(Type):
    class Parameter:
        pass

    def set_return_type(self, type: Type) -> FunctionType: ...

    def add_parameter(self, type: Type) -> Optional[FunctionType.Parameter]: ...

class TypeDef(Type):
    pass

class StructType(Type):
    class TYPE(enum.Enum):
        CLASS = 0

        STRUCT = 1

        UNION = 2

    class Member:
        pass

    def set_size(self, size: int) -> StructType: ...

    def add_member(self, name: str, type: Type, offset: int = -1) -> Optional[StructType.Member]: ...

class Function:
    class range_t:
        @overload
        def __init__(self) -> None: ...

        @overload
        def __init__(self, start: int, end: int) -> None: ...

        start: int

        end: int

    class Parameter:
        pass

    class LexicalBlock:
        pass

    class Label:
        pass

    def set_address(self, addr: int) -> Function: ...

    def set_low_high(self, low: int, high: int) -> Function: ...

    def set_ranges(self, ranges: Sequence[Function.range_t]) -> Function: ...

    def set_external(self) -> Function: ...

    def set_return_type(self, type: Type) -> Function: ...

    def add_parameter(self, name: str, type: Type) -> Optional[Function.Parameter]: ...

    def create_stack_variable(self, name: str) -> Optional[Variable]: ...

    def add_lexical_block(self, start: int, end: int) -> Optional[Function.LexicalBlock]: ...

    def add_label(self, addr: int, label: str) -> Optional[Function.Label]: ...

class Variable:
    def set_addr(self, addr: int) -> Variable: ...

    def set_stack_offset(self, offset: int) -> Variable: ...

    def set_external(self) -> Variable: ...

    def set_type(self, type: Type) -> Variable: ...

class CompilationUnit:
    def set_producer(self, arg: str, /) -> CompilationUnit: ...

    def create_function(self, name: str) -> Optional[Function]: ...

    def create_variable(self, name: str) -> Optional[Variable]: ...

    def create_generic_type(self, name: str) -> Optional[Type]: ...

    def create_enum(self, name: str) -> Optional[EnumType]: ...

    def create_typedef(self, name: str, ty: Type) -> Optional[TypeDef]: ...

    def create_structure(self, name: str, kind: StructType.TYPE = StructType.TYPE.STRUCT) -> Optional[StructType]: ...

    def create_base_type(self, name: str, size: int, encoding: BaseType.ENCODING = BaseType.ENCODING.NONE) -> Optional[BaseType]: ...

    def create_function_type(self, name: str) -> Optional[FunctionType]: ...

    def create_pointer_type(self, ty: Type) -> Optional[PointerType]: ...

    def create_void_type(self) -> Optional[Type]: ...

    def create_array(self, name: str, ty: Type, count: int) -> Optional[ArrayType]: ...
