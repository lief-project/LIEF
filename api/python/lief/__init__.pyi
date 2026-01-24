from collections.abc import Sequence
import enum
import io
import lief
import lief.PE
import os
from typing import Iterator, Optional, Union, overload

import lief.ELF
import lief.MachO

from . import (
    ART as ART,
    Android as Android,
    COFF as COFF,
    DEX as DEX,
    ELF as ELF,
    MachO as MachO,
    OAT as OAT,
    PE as PE,
    VDEX as VDEX,
    assembly as assembly,
    dsc as dsc,
    dwarf as dwarf,
    logging as logging,
    objc as objc,
    pdb as pdb
)


__tag__: str = ...

__commit__: str = ...

__is_tagged__: bool = ...

class lief_version_t:
    major: int

    minor: int

    patch: int

    id: int

    def __repr__(self) -> str: ...

    def __str__(self) -> str: ...

def disable_leak_warning() -> None: ...

def demangle(mangled: str) -> Optional[str]: ...

def dump(buffer: memoryview, title: str = '', prefix: str = '', limit: int = 0) -> str: ...

def extended_version_info() -> str: ...

def extended_version() -> lief_version_t: ...

__extended__: bool = ...

class range_t:
    low: int

    high: int

    @property
    def size(self) -> int: ...

    def __repr__(self) -> str: ...

    def __str__(self) -> str: ...

class debug_location_t:
    line: int

    file: str

    def __repr__(self) -> str: ...

class PLATFORMS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> PLATFORMS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    UNKNOWN = 3

    LINUX = 1

    ANDROID = 2

    WINDOWS = 3

    IOS = 4

    OSX = 5

def current_platform() -> PLATFORMS: ...

class Object:
    def __hash__(self) -> int: ...

    def __eq__(self, arg, /) -> bool: ...

class ok_t:
    def __bool__(self) -> bool: ...

class ok_error_t:
    @property
    def is_error(self) -> bool: ...

    @property
    def is_value(self) -> bool: ...

    @property
    def error(self) -> lief_errors: ...

    @property
    def value(self) -> ok_t: ...

    def __bool__(self) -> bool: ...

class lief_errors(enum.Enum):
    read_error = 1

    not_found = 2

    not_implemented = 3

    not_supported = 4

    corrupted = 5

    conversion_error = 6

    read_out_of_bound = 7

    asn1_bad_tag = 8

    file_error = 9

    file_format_error = 10

    parsing_error = 11

    build_error = 12

    data_too_large = 13

    require_extended_version = 14

@overload
def hash(arg: Object, /) -> int: ... # type: ignore

@overload
def hash(arg: Sequence[int], /) -> int: ... # type: ignore

@overload
def hash(arg: bytes, /) -> int: ... # type: ignore

@overload
def hash(arg: str, /) -> int: ... # type: ignore

def to_json(arg: Object, /) -> str: ...

class BinaryStream:
    @property
    def size(self) -> int: ...

    def __bool__(self) -> bool: ...

    def __len__(self) -> int: ...

    @property
    def pos(self) -> int: ...

    def increment_pos(self, value: int) -> BinaryStream: ...

    def decrement_pos(self, value: int) -> None: ...

    def setpos(self, value: int) -> None: ...

    def read_uleb128(self) -> tuple[Union[int,lief.lief_errors], int]: ...

    def read_sleb128(self) -> tuple[Union[int,lief.lief_errors], int]: ...

    def read_dwarf_encoded(self, encoding: int) -> Union[int,lief.lief_errors]: ...

    def read_string(self, maxsize: int = 18446744073709551615) -> Union[str,lief.lief_errors]: ...

    def peek_string(self, maxsize: int = 18446744073709551615) -> Union[str,lief.lief_errors]: ...

    def peek_string_at(self, offset: int, maxsize: int = 18446744073709551615) -> Union[str,lief.lief_errors]: ...

    @overload
    def read_u16string(self) -> Union[str,lief.lief_errors]: ...

    @overload
    def read_u16string(self, length: int) -> Union[str,lief.lief_errors]: ...

    @overload
    def peek_u16string(self) -> Union[str,lief.lief_errors]: ...

    @overload
    def peek_u16string(self, length: int) -> Union[str,lief.lief_errors]: ...

    @overload
    def peek_u16string(self, offset: int, length: int) -> Union[str,lief.lief_errors]: ...

    def read_mutf8(self, maxsize: int = 18446744073709551615) -> Union[str,lief.lief_errors]: ...

    def peek_data(self, offset: int, size: int, virtual_address: int = 0) -> bytes | None: ...

    @overload
    def read_data(self, size: int) -> bytes | None: ...

    @overload
    def read_data(self) -> bytes | None: ...

    def align(self, align_on: int) -> int: ...

    def set_endian_swap(self, swap: bool) -> None: ...

    def read_u8(self) -> Union[int,lief.lief_errors]: ...

    def read_i8(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u8(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u8(self, offset: int) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i8(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i8(self, offset: int) -> Union[int,lief.lief_errors]: ...

    def read_u16(self) -> Union[int,lief.lief_errors]: ...

    def read_i16(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u16(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u16(self, offset: int) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i16(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i16(self, offset: int) -> Union[int,lief.lief_errors]: ...

    def read_u32(self) -> Union[int,lief.lief_errors]: ...

    def read_i32(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u32(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u32(self, offset: int) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i32(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i32(self, offset: int) -> Union[int,lief.lief_errors]: ...

    def read_u64(self) -> Union[int,lief.lief_errors]: ...

    def read_i64(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u64(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_u64(self, offset: int) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i64(self) -> Union[int,lief.lief_errors]: ...

    @overload
    def peek_i64(self, offset: int) -> Union[int,lief.lief_errors]: ...

    @property
    def start(self) -> int: ...

    @property
    def start_addr(self) -> int: ...

    @property
    def end(self) -> int: ...

    @property
    def end_addr(self) -> int: ...

    @property
    def p(self) -> int: ...

    @property
    def p_addr(self) -> int: ...

class SpanStream(BinaryStream):
    @overload
    def slice(self, offset: int, size: int) -> Union[SpanStream,lief.lief_errors]: ...

    @overload
    def slice(self, offset: int) -> Union[SpanStream,lief.lief_errors]: ...

    def to_vector(self) -> Optional[VectorStream]: ...

    @property
    def content(self) -> bytes: ...

    @property
    def __bytes__(self) -> bytes: ...

class VectorStream(BinaryStream):
    @staticmethod
    def from_file(path: Union[str, os.PathLike]) -> Union[VectorStream,lief.lief_errors]: ...

    @staticmethod
    def from_bytes(buffer: bytes) -> Optional[VectorStream]: ...

    @property
    def content(self) -> memoryview: ...

    @overload
    def slice(self, arg0: int, arg1: int, /) -> Optional[SpanStream]: ...

    @overload
    def slice(self, arg: int, /) -> Optional[SpanStream]: ...

class FileStream(BinaryStream):
    @staticmethod
    def from_file(arg: Union[str, os.PathLike], /) -> Union[FileStream,lief.lief_errors]: ...

    @property
    def content(self) -> bytes: ...

class WriteStream:
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, endian_swap: bool) -> None: ...

    def reserve(self, size: int) -> WriteStream: ...

    def increase_capacity(self, size: int) -> WriteStream: ...

    def align(self, alignment: int, fill: int = 0) -> WriteStream: ...

    @property
    def size(self) -> int: ...

    def __len__(self) -> int: ...

    @property
    def tellp(self) -> int: ...

    def seekp(self, pos: int) -> WriteStream: ...

    def seek_end(self) -> WriteStream: ...

    def pad(self, size: int, value: int = 0) -> WriteStream: ...

    def set_endian_swap(self, swap: bool) -> None: ...

    @property
    def endian_swap(self) -> bool: ...

    @property
    def raw(self) -> memoryview: ...

    def __bytes__(self) -> bytes: ...

    def write_u8(self, arg: int, /) -> WriteStream: ...

    def write_i8(self, arg: int, /) -> WriteStream: ...

    def write_u16(self, arg: int, /) -> WriteStream: ...

    def write_i16(self, arg: int, /) -> WriteStream: ...

    def write_u32(self, arg: int, /) -> WriteStream: ...

    def write_i32(self, arg: int, /) -> WriteStream: ...

    def write_u64(self, arg: int, /) -> WriteStream: ...

    def write_i64(self, arg: int, /) -> WriteStream: ...

    def write_uleb128(self, value: int) -> WriteStream: ...

    def write_sleb128(self, value: int) -> WriteStream: ...

    @overload
    def write(self, s: str) -> WriteStream: ...

    @overload
    def write(self, buffer: bytes) -> WriteStream: ...

    @overload
    def write(self, buffer: Sequence[int]) -> WriteStream: ...

    @overload
    def write(self, other: WriteStream) -> WriteStream: ...

    def put(self, c: int) -> WriteStream: ...

class Header(Object):
    class ARCHITECTURES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.ARCHITECTURES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        ARM = 1

        ARM64 = 2

        MIPS = 3

        X86 = 4

        X86_64 = 5

        PPC = 6

        SPARC = 7

        SYSZ = 8

        XCORE = 9

        RISCV = 10

        LOONGARCH = 11

        PPC64 = 12

    class ENDIANNESS(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.ENDIANNESS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        BIG = 1

        LITTLE = 2

    class MODES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.MODES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        BITS_16 = 1

        BITS_32 = 2

        BITS_64 = 4

        THUMB = 8

        ARM64E = 16

    class OBJECT_TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> Header.OBJECT_TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        EXECUTABLE = 1

        LIBRARY = 2

        OBJECT = 3

    @property
    def architecture(self) -> Header.ARCHITECTURES: ...

    @property
    def modes(self) -> Header.MODES: ...

    @property
    def modes_list(self) -> list[Header.MODES]: ...

    @property
    def entrypoint(self) -> int: ...

    @property
    def object_type(self) -> Header.OBJECT_TYPES: ...

    @property
    def endianness(self) -> Header.ENDIANNESS: ...

    @property
    def is_32(self) -> bool: ...

    @property
    def is_64(self) -> bool: ...

    def __str__(self) -> str: ...

class Binary(Object):
    class VA_TYPES(enum.Enum):
        AUTO = 0

        RVA = 1

        VA = 2

    class FORMATS(enum.Enum):
        UNKNOWN = 0

        ELF = 1

        PE = 2

        MACHO = 3

        OAT = 4

    class it_sections:
        def __getitem__(self, arg: int, /) -> Section: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_sections: ...

        def __next__(self) -> Section: ...

    class it_symbols:
        def __getitem__(self, arg: int, /) -> Symbol: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_symbols: ...

        def __next__(self) -> Symbol: ...

    class it_relocations:
        def __getitem__(self, arg: int, /) -> Relocation: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_relocations: ...

        def __next__(self) -> Relocation: ...

    @property
    def debug_info(self) -> DebugInfo: ...

    @property
    def format(self) -> Binary.FORMATS: ...

    @property
    def is_pie(self) -> bool: ...

    @property
    def has_nx(self) -> bool: ...

    @property
    def header(self) -> Header: ...

    @property
    def entrypoint(self) -> int: ...

    def remove_section(self, name: str, clear: bool = False) -> None: ...

    @property
    def sections(self) -> Binary.it_sections: ...

    @property
    def relocations(self) -> Binary.it_relocations: ...

    @property
    def exported_functions(self) -> list[Function]: ...

    @property
    def imported_functions(self) -> list[Function]: ...

    @property
    def libraries(self) -> list[Union[str,bytes]]: ...

    @property
    def symbols(self) -> Binary.it_symbols: ...

    def has_symbol(self, symbol_name: str) -> bool: ...

    def get_symbol(self, symbol_name: str) -> Symbol: ...

    def get_function_address(self, function_name: str) -> Union[int, lief_errors]: ...

    @overload
    def patch_address(self, address: int, patch_value: Sequence[int], va_type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> None: ...

    @overload
    def patch_address(self, address: int, patch_value: int, size: int = 8, va_type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> None: ...

    def get_content_from_virtual_address(self, virtual_address: int, size: int, va_type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> memoryview: ...

    def get_int_from_virtual_address(self, address: int, interger_size: int, type: Binary.VA_TYPES = Binary.VA_TYPES.AUTO) -> Optional[int]: ...

    @property
    def abstract(self) -> lief.Binary: ...

    @property
    def concrete(self) -> lief.ELF.Binary | lief.PE.Binary | lief.MachO.Binary: ...

    @property
    def ctor_functions(self) -> list[Function]: ...

    def xref(self, virtual_address: int) -> list[int]: ...

    def offset_to_virtual_address(self, offset: int, slide: int = 0) -> Union[int, lief_errors]: ...

    @property
    def imagebase(self) -> int: ...

    @property
    def original_size(self) -> int: ...

    @overload
    def disassemble(self, address: int) -> Iterator[Optional[assembly.Instruction]]: ...

    @overload
    def disassemble(self, address: int, size: int) -> Iterator[Optional[assembly.Instruction]]: ...

    @overload
    def disassemble(self, function_name: str) -> Iterator[Optional[assembly.Instruction]]: ...

    def disassemble_from_bytes(self, buffer: bytes, address: int = 0) -> Iterator[Optional[assembly.Instruction]]: ...

    def assemble(self, address: int, assembly: str, config: assembly.AssemblerConfig = ...) -> bytes: ...

    @property
    def page_size(self) -> int: ...

    def load_debug_info(self, path: Union[str | os.PathLike]) -> DebugInfo: ...

    @property
    def virtual_size(self) -> int: ...

    def __str__(self) -> str: ...

class Section(Object):
    name: Union[str, bytes]

    @property
    def fullname(self) -> bytes: ...

    size: int

    offset: int

    virtual_address: int

    content: memoryview

    @property
    def entropy(self) -> float: ...

    @overload
    def search(self, number: int, pos: int = 0, size: int = 0) -> Optional[int]: ...

    @overload
    def search(self, str: str, pos: int = 0) -> Optional[int]: ...

    @overload
    def search(self, bytes: bytes, pos: int = 0) -> Optional[int]: ...

    @overload
    def search_all(self, number: int, size: int = 0) -> list[int]: ...

    @overload
    def search_all(self, str: str) -> list[int]: ...

    def __str__(self) -> str: ...

class Symbol(Object):
    name: Union[str, bytes]

    value: int

    size: int

    def __str__(self) -> str: ...

def parse(obj: Union[str | io.IOBase | os.PathLike | bytes | list[int]]) -> PE.Binary | OAT.Binary | ELF.Binary | MachO.Binary | COFF.Binary | None: ...

class Relocation(Object):
    address: int

    size: int

    def __str__(self) -> str: ...

class Function(Symbol):
    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, arg: str, /) -> None: ...

    @overload
    def __init__(self, arg: int, /) -> None: ...

    @overload
    def __init__(self, arg0: str, arg1: int, /) -> None: ...

    class FLAGS(enum.Flag):
        @staticmethod
        def from_value(arg: int, /) -> Function.FLAGS: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        NONE = 0

        IMPORTED = 16

        EXPORTED = 8

        CONSTRUCTOR = 1

        DESTRUCTOR = 2

        DEBUG_INFO = 4

    def add(self, flag: Function.FLAGS) -> Function: ...

    def has(self, flag: Function.FLAGS) -> bool: ...

    @property
    def flags(self) -> Function.FLAGS: ...

    @property
    def flags_list(self) -> list[Function.FLAGS]: ...

    address: int

    def __str__(self) -> str: ...

class DebugInfo:
    class FORMAT(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> DebugInfo.FORMAT: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        UNKNOWN = 0

        DWARF = 1

        PDB = 2

    @property
    def format(self) -> DebugInfo.FORMAT: ...

    def find_function_address(self, name: str) -> int | None: ...

def is_pdb(file: Union[str | os.PathLike]) -> bool: ...

def is_shared_cache(file: Union[str | os.PathLike]) -> bool: ...

@overload
def is_elf(filename: Union[str | os.PathLike]) -> bool: ...

@overload
def is_elf(raw: Sequence[int]) -> bool: ...

@overload
def is_pe(file: Union[str | os.PathLike]) -> bool: ...

@overload
def is_pe(raw: Sequence[int]) -> bool: ...

@overload
def is_macho(filename: Union[str | os.PathLike]) -> bool: ...

@overload
def is_macho(raw: Sequence[int]) -> bool: ...

@overload
def is_oat(binary: ELF.Binary) -> bool: ...

@overload
def is_oat(path: str) -> bool: ...

@overload
def is_oat(raw: Sequence[int]) -> bool: ...

@overload
def is_dex(path: str) -> bool: ...

@overload
def is_dex(raw: Sequence[int]) -> bool: ...

@overload
def is_vdex(path: str) -> bool: ...

@overload
def is_vdex(raw: Sequence[int]) -> bool: ...

@overload
def is_art(path: str) -> bool: ...

@overload
def is_art(raw: Sequence[int]) -> bool: ...

def is_coff(file: Union[str | os.PathLike]) -> bool: ...
