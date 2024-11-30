from collections.abc import Sequence
import enum
import io
import os
from typing import Iterator, Optional, Union, overload

import lief


class Binary(lief.ELF.Binary):
    class it_dex_files:
        def __getitem__(self, arg: int, /) -> lief.DEX.File: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_dex_files: ...

        def __next__(self) -> lief.DEX.File: ...

    class it_oat_dex_files:
        def __getitem__(self, arg: int, /) -> DexFile: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_oat_dex_files: ...

        def __next__(self) -> DexFile: ...

    class it_classes:
        def __getitem__(self, arg: int, /) -> Class: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_classes: ...

        def __next__(self) -> Class: ...

    class it_methods:
        def __getitem__(self, arg: int, /) -> Method: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Binary.it_methods: ...

        def __next__(self) -> Method: ...

    @property
    def header(self) -> Header: ... # type: ignore

    @property
    def dex_files(self) -> Binary.it_dex_files: ...

    @property
    def oat_dex_files(self) -> Binary.it_oat_dex_files: ...

    @property
    def classes(self) -> Binary.it_classes: ...

    @property
    def methods(self) -> Binary.it_methods: ...

    def has_class(self, arg: str, /) -> bool: ...

    @overload
    def get_class(self, class_name: str) -> Class: ...

    @overload
    def get_class(self, class_index: int) -> Class: ...

    @property
    def dex2dex_json_info(self) -> str: ...

    def __str__(self) -> str: ...

class Class(lief.Object):
    def __init__(self) -> None: ...

    class it_methods:
        def __getitem__(self, arg: int, /) -> Method: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Class.it_methods: ...

        def __next__(self) -> Method: ...

    def has_dex_class(self) -> bool: ...

    @property
    def status(self) -> OAT_CLASS_STATUS: ...

    @property
    def type(self) -> OAT_CLASS_TYPES: ...

    @property
    def fullname(self) -> str: ...

    @property
    def index(self) -> int: ...

    @property
    def methods(self) -> Class.it_methods: ...

    @property
    def bitmap(self) -> list[int]: ...

    @overload
    def is_quickened(self, dex_method: lief.DEX.Method) -> bool: ...

    @overload
    def is_quickened(self, method_index: int) -> bool: ...

    @overload
    def method_offsets_index(self, arg: lief.DEX.Method, /) -> int: ...

    @overload
    def method_offsets_index(self, arg: int, /) -> int: ...

    def __str__(self) -> str: ...

class DexFile(lief.Object):
    def __init__(self) -> None: ...

    location: str

    checksum: int

    dex_offset: int

    @property
    def has_dex_file(self) -> bool: ...

    @property
    def dex_file(self) -> lief.DEX.File: ...

    def __str__(self) -> str: ...

class HEADER_KEYS(enum.Enum):
    IMAGE_LOCATION = 0

    DEX2OAT_CMD_LINE = 1

    DEX2OAT_HOST = 2

    PIC = 3

    HAS_PATCH_INFO = 4

    DEBUGGABLE = 5

    NATIVE_DEBUGGABLE = 6

    COMPILER_FILTER = 7

    CLASS_PATH = 8

    BOOT_CLASS_PATH = 9

    CONCURRENT_COPYING = 10

class Header(lief.Object):
    def __init__(self) -> None: ...

    class it_key_values_t:
        def __getitem__(self, arg: int, /) -> Header.element_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> Header.it_key_values_t: ...

        def __next__(self) -> Header.element_t: ...

    class element_t:
        key: lief.OAT.HEADER_KEYS

        value: str

    @property
    def key_values(self) -> Header.it_key_values_t: ...

    @property
    def keys(self) -> list[HEADER_KEYS]: ...

    @property
    def values(self) -> list[str]: ...

    @property
    def magic(self) -> list[int]: ...

    @property
    def version(self) -> int: ...

    @property
    def checksum(self) -> int: ...

    @property
    def instruction_set(self) -> INSTRUCTION_SETS: ...

    @property
    def nb_dex_files(self) -> int: ...

    @property
    def oat_dex_files_offset(self) -> int: ...

    @property
    def executable_offset(self) -> int: ...

    @property
    def i2i_bridge_offset(self) -> int: ...

    @property
    def i2c_code_bridge_offset(self) -> int: ...

    @property
    def jni_dlsym_lookup_offset(self) -> int: ...

    @property
    def quick_generic_jni_trampoline_offset(self) -> int: ...

    @property
    def quick_imt_conflict_trampoline_offset(self) -> int: ...

    @property
    def quick_resolution_trampoline_offset(self) -> int: ...

    @property
    def quick_to_interpreter_bridge_offset(self) -> int: ...

    @property
    def image_patch_delta(self) -> int: ...

    @property
    def image_file_location_oat_checksum(self) -> int: ...

    @property
    def image_file_location_oat_data_begin(self) -> int: ...

    @property
    def key_value_size(self) -> int: ...

    def get(self, key: HEADER_KEYS) -> str: ...

    def set(self, key: HEADER_KEYS, value: str) -> Header: ...

    def __getitem__(self, arg: HEADER_KEYS, /) -> str: ...

    def __setitem__(self, arg0: HEADER_KEYS, arg1: str, /) -> Header: ...

    def __str__(self) -> str: ...

class INSTRUCTION_SETS(enum.Enum):
    NONE = 0

    ARM = 1

    ARM_64 = 2

    THUMB2 = 3

    X86 = 4

    X86_64 = 5

    MIPS = 6

    MIPS_64 = 7

class Method(lief.Object):
    def __init__(self) -> None: ...

    @property
    def name(self) -> str: ...

    @property
    def oat_class(self) -> Class: ...

    @property
    def dex_method(self) -> lief.DEX.Method: ...

    @property
    def has_dex_method(self) -> bool: ...

    @property
    def is_dex2dex_optimized(self) -> bool: ...

    @property
    def is_compiled(self) -> bool: ...

    quick_code: list[int]

    def __str__(self) -> str: ...

class OAT_CLASS_STATUS(enum.Enum):
    RETIRED = -2

    ERROR = -1

    NOTREADY = 0

    IDX = 1

    LOADED = 2

    RESOLVING = 3

    RESOLVED = 4

    VERIFYING = 5

    VERIFICATION_AT_RUNTIME = 6

    VERIFYING_AT_RUNTIME = 7

    VERIFIED = 8

    INITIALIZING = 9

    INITIALIZED = 10

class OAT_CLASS_TYPES(enum.Enum):
    ALL_COMPILED = 0

    SOME_COMPILED = 1

    NONE_COMPILED = 2

def android_version(arg: int, /) -> lief.Android.ANDROID_VERSIONS: ...

@overload
def parse(oat_file: str) -> Optional[Binary]: ...

@overload
def parse(oat_file: str, vdex_file: str) -> Optional[Binary]: ...

@overload
def parse(raw: Sequence[int]) -> Optional[Binary]: ...

@overload
def parse(obj: Union[io.IOBase | os.PathLike]) -> Optional[Binary]: ...

@overload
def version(binary: lief.ELF.Binary) -> int: ...

@overload
def version(file: str) -> int: ...

@overload
def version(raw: Sequence[int]) -> int: ...
