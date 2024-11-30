from collections.abc import Sequence
import enum
import io
import os
from typing import Iterator, Optional, Union, overload

import lief


class ACCESS_FLAGS(enum.Enum):
    UNKNOWN = 0

    PUBLIC = 1

    PRIVATE = 2

    PROTECTED = 4

    STATIC = 8

    FINAL = 16

    SYNCHRONIZED = 32

    VOLATILE = 64

    BRIDGE = 64

    TRANSIENT = 128

    VARARGS = 128

    NATIVE = 256

    INTERFACE = 512

    ABSTRACT = 1024

    STRICT = 2048

    SYNTHETIC = 4096

    ANNOTATION = 8192

    ENUM = 16384

    CONSTRUCTOR = 65536

    DECLARED_SYNCHRONIZED = 131072

class Class(lief.Object):
    class it_methods:
        def __getitem__(self, arg: int, /) -> Method: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Class.it_methods: ...

        def __next__(self) -> Method: ...

    class it_fields:
        def __getitem__(self, arg: int, /) -> Field: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Class.it_fields: ...

        def __next__(self) -> Field: ...

    class it_named_methods:
        def __getitem__(self, arg: int, /) -> Method: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Class.it_named_methods: ...

        def __next__(self) -> Method: ...

    class it_named_fields:
        def __getitem__(self, arg: int, /) -> Field: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Class.it_named_fields: ...

        def __next__(self) -> Field: ...

    @property
    def fullname(self) -> str: ...

    @property
    def pretty_name(self) -> str: ...

    @property
    def name(self) -> str: ...

    @property
    def source_filename(self) -> str: ...

    @property
    def package_name(self) -> str: ...

    @property
    def has_parent(self) -> bool: ...

    @property
    def parent(self) -> Class: ...

    @property
    def methods(self) -> Class.it_methods: ...

    def get_method(self, name: str) -> Class.it_named_methods: ...

    @property
    def fields(self) -> Class.it_fields: ...

    def get_field(self, name: str) -> Class.it_named_fields: ...

    @property
    def access_flags(self) -> list[ACCESS_FLAGS]: ...

    @property
    def dex2dex_info(self) -> dict[Method, dict[int, int]]: ...

    @property
    def index(self) -> int: ...

    def has(self, flag: ACCESS_FLAGS) -> bool: ...

    def __str__(self) -> str: ...

class CodeInfo(lief.Object):
    def __str__(self) -> str: ...

class Field(lief.Object):
    @property
    def name(self) -> str: ...

    @property
    def index(self) -> int: ...

    @property
    def has_class(self) -> bool: ...

    @property
    def cls(self) -> Class: ...

    @property
    def is_static(self) -> bool: ...

    @property
    def type(self) -> Type: ...

    @property
    def access_flags(self) -> list[ACCESS_FLAGS]: ...

    def has(self, flag: ACCESS_FLAGS) -> bool: ...

    def __str__(self) -> str: ...

class File(lief.Object):
    class it_classes:
        def __getitem__(self, arg: int, /) -> Class: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> File.it_classes: ...

        def __next__(self) -> Class: ...

    class it_methods:
        def __getitem__(self, arg: int, /) -> Method: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> File.it_methods: ...

        def __next__(self) -> Method: ...

    class it_strings:
        def __getitem__(self, arg: int, /) -> str: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> File.it_strings: ...

        def __next__(self) -> str: ...

    class it_types:
        def __getitem__(self, arg: int, /) -> Type: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> File.it_types: ...

        def __next__(self) -> Type: ...

    class it_prototypes:
        def __getitem__(self, arg: int, /) -> Prototype: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> File.it_prototypes: ...

        def __next__(self) -> Prototype: ...

    class it_fields:
        def __getitem__(self, arg: int, /) -> Field: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> File.it_fields: ...

        def __next__(self) -> Field: ...

    @property
    def version(self) -> int: ...

    @property
    def header(self) -> Header: ...

    @property
    def classes(self) -> File.it_classes: ...

    def has_class(self, classname: str) -> bool: ...

    @overload
    def get_class(self, classname: str) -> Class: ...

    @overload
    def get_class(self, classname: int) -> Class: ...

    @property
    def methods(self) -> File.it_methods: ...

    @property
    def fields(self) -> File.it_fields: ...

    @property
    def strings(self) -> File.it_strings: ...

    @property
    def types(self) -> File.it_types: ...

    @property
    def prototypes(self) -> File.it_prototypes: ...

    @property
    def map(self) -> MapList: ...

    def raw(self, deoptimize: bool = True) -> list[int]: ...

    name: str

    location: str

    @property
    def dex2dex_json_info(self) -> str: ...

    def save(self, output: str = '', deoptimize: bool = True) -> str: ...

    def __str__(self) -> str: ...

class Header(lief.Object):
    @property
    def magic(self) -> list[int]: ...

    @property
    def checksum(self) -> int: ...

    @property
    def signature(self) -> list[int]: ...

    @property
    def file_size(self) -> int: ...

    @property
    def header_size(self) -> int: ...

    @property
    def endian_tag(self) -> int: ...

    @property
    def map_offset(self) -> int: ...

    @property
    def strings(self) -> tuple[int, int]: ...

    @property
    def link(self) -> tuple[int, int]: ...

    @property
    def types(self) -> tuple[int, int]: ...

    @property
    def prototypes(self) -> tuple[int, int]: ...

    @property
    def fields(self) -> tuple[int, int]: ...

    @property
    def methods(self) -> tuple[int, int]: ...

    @property
    def classes(self) -> tuple[int, int]: ...

    @property
    def data(self) -> tuple[int, int]: ...

    @property
    def nb_classes(self) -> int: ...

    @property
    def nb_methods(self) -> int: ...

    def __str__(self) -> str: ...

class MapItem(lief.Object):
    class TYPES(enum.Enum):
        @staticmethod
        def from_value(arg: int, /) -> MapItem.TYPES: ...

        def __eq__(self, arg, /) -> bool: ...

        def __ne__(self, arg, /) -> bool: ...

        def __int__(self) -> int: ...

        HEADER = 0

        STRING_ID = 1

        TYPE_ID = 2

        PROTO_ID = 3

        FIELD_ID = 4

        METHOD_ID = 5

        CLASS_DEF = 6

        CALL_SITE_ID = 7

        METHOD_HANDLE = 8

        MAP_LIST = 4096

        TYPE_LIST = 4097

        ANNOTATION_SET_REF_LIST = 4098

        ANNOTATION_SET = 4099

        CLASS_DATA = 8192

        CODE = 8193

        STRING_DATA = 8194

        DEBUG_INFO = 8195

        ANNOTATION = 8196

        ENCODED_ARRAY = 8197

        ANNOTATIONS_DIRECTORY = 8198

    @property
    def type(self) -> MapItem.TYPES: ...

    @property
    def offset(self) -> int: ...

    @property
    def size(self) -> int: ...

    def __str__(self) -> str: ...

class MapList(lief.Object):
    class it_items_t:
        def __getitem__(self, arg: int, /) -> MapItem: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> MapList.it_items_t: ...

        def __next__(self) -> MapItem: ...

    @property
    def items(self) -> MapList.it_items_t: ...

    def has(self, type: MapItem.TYPES) -> bool: ...

    def get(self, type: MapItem.TYPES) -> MapItem: ...

    def __getitem__(self, arg: MapItem.TYPES, /) -> MapItem: ...

    def __str__(self) -> str: ...

class Method(lief.Object):
    @property
    def name(self) -> str: ...

    @property
    def index(self) -> int: ...

    @property
    def has_class(self) -> bool: ...

    @property
    def cls(self) -> Class: ...

    @property
    def code_offset(self) -> int: ...

    @property
    def bytecode(self) -> list[int]: ...

    @property
    def is_virtual(self) -> bool: ...

    @property
    def prototype(self) -> Prototype: ...

    @property
    def access_flags(self) -> list[ACCESS_FLAGS]: ...

    def has(self, flag: ACCESS_FLAGS) -> bool: ...

    def insert_dex2dex_info(self, pc: int, index: int) -> None: ...

    def __str__(self) -> str: ...

class Prototype(lief.Object):
    class it_params:
        def __getitem__(self, arg: int, /) -> Type: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Prototype.it_params: ...

        def __next__(self) -> Type: ...

    @property
    def return_type(self) -> Type: ...

    @property
    def parameters_type(self) -> Prototype.it_params: ...

    def __str__(self) -> str: ...

class Type(lief.Object):
    class TYPES(enum.Enum):
        UNKNOWN = 0

        ARRAY = 3

        PRIMITIVE = 1

        CLASS = 2

    class PRIMITIVES(enum.Enum):
        VOID_T = 1

        BOOLEAN = 2

        BYTE = 3

        SHORT = 4

        CHAR = 5

        INT = 6

        LONG = 7

        FLOAT = 8

        DOUBLE = 9

    @property
    def type(self) -> Type.TYPES: ...

    @property
    def value(self) -> object: ...

    @property
    def dim(self) -> int: ...

    @property
    def underlying_array_type(self) -> Type: ...

    @staticmethod
    def pretty_name(primitive: Type.PRIMITIVES) -> str: ...

    def __str__(self) -> str: ...

@overload
def parse(filename: str) -> Optional[File]: ...

@overload
def parse(raw: Sequence[int], name: str = '') -> Optional[File]: ...

@overload
def parse(obj: Union[io.IOBase | os.PathLike], name: str = '') -> Optional[File]: ...

@overload
def version(file: str) -> int: ...

@overload
def version(raw: Sequence[int]) -> int: ...
