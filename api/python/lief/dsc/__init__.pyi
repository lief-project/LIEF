from collections.abc import Sequence
import enum
import os
from typing import Iterator, Optional, Union, overload

import lief


class DyldSharedCache:
    class VERSION(enum.Enum):
        UNKNOWN = 0

        DYLD_95_3 = 1

        DYLD_195_5 = 2

        DYLD_239_3 = 3

        DYLD_360_14 = 4

        DYLD_421_1 = 5

        DYLD_832_7_1 = 6

        DYLD_940 = 7

        DYLD_1042_1 = 8

        UNRELEASED = 9

    class PLATFORM(enum.Enum):
        UNKNOWN = 0

        MACOS = 1

        IOS = 2

        TVOS = 3

        WATCHOS = 4

        BRIDGEOS = 5

        IOSMAC = 6

        IOS_SIMULATOR = 7

        TVOS_SIMULATOR = 8

        WATCHOS_SIMULATOR = 9

        DRIVERKIT = 10

        VISIONOS = 11

        VISIONOS_SIMULATOR = 12

        FIRMWARE = 13

        SEPOS = 14

        ANY = 4294967295

    class ARCH(enum.Enum):
        UNKNOWN = 0

        I386 = 1

        X86_64 = 2

        X86_64H = 3

        ARMV5 = 4

        ARMV6 = 5

        ARMV7 = 6

        ARM64 = 7

        ARM64E = 8

    @staticmethod
    def from_path(path: str, arch: str = '') -> Optional[DyldSharedCache]: ...

    @staticmethod
    def from_files(files: Sequence[str]) -> Optional[DyldSharedCache]: ...

    @property
    def filename(self) -> str: ...

    @property
    def version(self) -> DyldSharedCache.VERSION: ...

    @property
    def filepath(self) -> str: ...

    @property
    def load_address(self) -> int: ...

    @property
    def arch_name(self) -> str: ...

    @property
    def platform(self) -> DyldSharedCache.PLATFORM: ...

    @property
    def arch(self) -> DyldSharedCache.ARCH: ...

    @property
    def has_subcaches(self) -> bool: ...

    def find_lib_from_va(self, virtual_address: int) -> Optional[Dylib]: ...

    def find_lib_from_path(self, path: str) -> Optional[Dylib]: ...

    def find_lib_from_name(self, name: str) -> Optional[Dylib]: ...

    @property
    def libraries(self) -> Sequence[Optional[Dylib]]: ...

    @property
    def mapping_info(self) -> Sequence[Optional[MappingInfo]]: ...

    @property
    def subcaches(self) -> Sequence[Optional[SubCache]]: ...

    def get_content_from_va(self, addr: int, size: int) -> bytes: ...

    def cache_for_address(self, address: int) -> Optional[DyldSharedCache]: ...

    @property
    def main_cache(self) -> Optional[DyldSharedCache]: ...

    def find_subcache(self, filename: str) -> Optional[DyldSharedCache]: ...

    def va_to_offset(self, virtual_address: int) -> Union[int, lief.lief_errors]: ...

    def disassemble(self, arg: int, /) -> Iterator[Optional[lief.assembly.Instruction]]: ...

    def enable_caching(self, target_dir: str) -> None: ...

    def flush_cache(self) -> None: ...

class Dylib:
    class extract_opt_t:
        def __init__(self) -> None: ...

        pack: bool

        fix_branches: bool

        fix_memory: bool

        fix_relocations: bool

        fix_objc: bool

        create_dyld_chained_fixup_cmd: bool

    @property
    def path(self) -> str: ...

    @property
    def address(self) -> int: ...

    @property
    def modtime(self) -> int: ...

    @property
    def inode(self) -> int: ...

    @property
    def padding(self) -> int: ...

    def get(self, opt: Dylib.extract_opt_t = ...) -> Optional[lief.MachO.Binary]: ...

class MappingInfo:
    @property
    def address(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def end_address(self) -> int: ...

    @property
    def file_offset(self) -> int: ...

    @property
    def max_prot(self) -> int: ...

    @property
    def init_prot(self) -> int: ...

class SubCache:
    @property
    def uuid(self) -> list[int]: ...

    @property
    def vm_offset(self) -> int: ...

    @property
    def suffix(self) -> str: ...

    @property
    def cache(self) -> Optional[DyldSharedCache]: ...

@overload
def enable_cache() -> bool: ...

@overload
def enable_cache(target_cache_dir: str) -> bool: ...

@overload
def load(files: Sequence[str]) -> Optional[DyldSharedCache]: ...

@overload
def load(path: os.PathLike, arch: str = '') -> Optional[DyldSharedCache]: ...
