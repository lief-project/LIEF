import enum
from collections.abc import Iterator, Mapping
from typing import Any, Final, Optional, overload

import lief
import lief.assembly
from lief.runtime import (
    android as android,
)
from lief.runtime import (
    linux as linux,
)
from lief.runtime import (
    osx as osx,
)
from lief.runtime import (
    windows as windows,
)


class ARCH(enum.Enum):
    NONE = 0

    X86_64 = 1

    ARM64 = 2

    RISCV64 = 3


class PLATFORMS(enum.Enum):
    NONE = 0

    LINUX = 1

    WINDOWS = 2

    ANDROID = 3

    OSX = 4

    IOS = 5


enabled: bool = ...

platform: PLATFORMS = ...

arch: ARCH = ...


class Host:
    name: Final[str] = ...

    home_dir: Final[str] = ...

    tmp_dir: Final[str] = ...

    config_dir: Final[str] = ...

    cache_dir: Final[str] = ...


class Process:
    class EnvVars:
        @property
        def vars(self) -> dict[str, str]: ...

        @vars.setter
        def vars(self, arg: Mapping[str, str], /) -> None: ...

    pid: Final[int] = ...

    tid: Final[int] = ...

    arch: Final[ARCH] = ...

    page_size: Final[int] = ...

    platform: Final[PLATFORMS] = ...

    @staticmethod
    def get_env(key: str) -> str | None: ...

    envs: Final[Process.EnvVars] = ...


class Module:
    @property
    def name(self) -> str: ...

    @property
    def path(self) -> str: ...

    @property
    def imagebase(self) -> int: ...

    @property
    def end(self) -> int: ...

    @property
    def size(self) -> int: ...

    def contains(self, addr: int) -> bool: ...

    @overload
    def dump(self) -> bytes: ...

    @overload
    def dump(self, filepath: str) -> bytes: ...

    def __str__(self) -> str: ...


def modules() -> Iterator[Optional[Module]]: ...


def module_from_name(name: str) -> Optional[Module]: ...


def module_from_path(path: str) -> Optional[Module]: ...


def module_from_addr(addr: int) -> Optional[Module]: ...


class Memory:
    class MMAP_FLAGS(enum.IntFlag):
        def __repr__(self, /): ...

        NONE = 0

        PRIVATE = 1

        ANONYMOUS = 2

        SHARED = 4

        FIXED = 8

        JIT = 16

    NONE: Memory.PERM = ...

    PRIVATE: Memory.MMAP_FLAGS = ...

    ANONYMOUS: Memory.MMAP_FLAGS = ...

    SHARED: Memory.MMAP_FLAGS = ...

    FIXED: Memory.MMAP_FLAGS = ...

    JIT: Memory.MMAP_FLAGS = ...

    class PERM(enum.IntFlag):
        def __repr__(self, /): ...

        NONE = 0

        READ = 1

        WRITE = 2

        EXEC = 4

    READ: Memory.PERM = ...

    WRITE: Memory.PERM = ...

    EXEC: Memory.PERM = ...

    class Chunk:
        @overload
        def __init__(self, addr: Any, size: int, permissions: int) -> None: ...

        @overload
        def __init__(self, addr: Any, size: int) -> None: ...

        @overload
        def __init__(self, addr: Any) -> None: ...

        @property
        def addr_ptr(self) -> Any: ...

        @property
        def addr(self) -> int: ...

        @property
        def size(self) -> int: ...

        @property
        def permissions(self) -> int: ...

        @property
        def page_start(self) -> int: ...

        @property
        def page_end(self) -> int: ...

        def change_permissions(self, permission: int) -> Memory.Chunk: ...

        def make_x(self) -> Memory.Chunk: ...

        def make_rw(self) -> Memory.Chunk: ...

        def make_rx(self) -> Memory.Chunk: ...

        def make_rwx(self) -> Memory.Chunk: ...

        def make_ro(self) -> Memory.Chunk: ...

        def cache_flush(self) -> Memory.Chunk: ...

        def is_valid(self) -> bool: ...

        def __bool__(self) -> bool: ...

        def deallocate(self) -> lief.ok_error_t: ...

        def __str__(self) -> str: ...

    @staticmethod
    def mmap(size: int, flags: int, permissions: int = 0) -> Memory.Chunk | None: ...

    @staticmethod
    def mmap_hint(
        hint: int, size: int, flags: int, permissions: int = 0
    ) -> Memory.Chunk | None: ...

    @staticmethod
    def munmap(chunk: Memory.Chunk) -> lief.ok_error_t: ...

    @staticmethod
    def mprotect(chunk: Memory.Chunk, flags: int) -> lief.ok_error_t: ...

    @staticmethod
    def perm_str(flags: int) -> str: ...

    @overload
    @staticmethod
    def write(ptr: Any, size: int, addr: int) -> lief.ok_error_t: ...

    @overload
    @staticmethod
    def write(buffer: memoryview, addr: int) -> lief.ok_error_t: ...

    @overload
    @staticmethod
    def write(buffer: bytes, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_u8(value: int, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_i8(value: int, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_u16(value: int, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_i16(value: int, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_u32(value: int, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_i32(value: int, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_u64(value: int, addr: int) -> lief.ok_error_t: ...

    @staticmethod
    def write_i64(value: int, addr: int) -> lief.ok_error_t: ...

    @overload
    @staticmethod
    def read(addr: int, size: int) -> bytes: ...

    @overload
    @staticmethod
    def read(addr: int, out: Any, size: int) -> None: ...

    @staticmethod
    def read_u8(addr: int) -> int: ...

    @staticmethod
    def read_i8(addr: int) -> int: ...

    @staticmethod
    def read_u16(addr: int) -> int: ...

    @staticmethod
    def read_i16(addr: int) -> int: ...

    @staticmethod
    def read_u32(addr: int) -> int: ...

    @staticmethod
    def read_i32(addr: int) -> int: ...

    @staticmethod
    def read_u64(addr: int) -> int: ...

    @staticmethod
    def read_i64(addr: int) -> int: ...


def disassemble(addr: int) -> Iterator[Optional[lief.assembly.Instruction]]: ...


def assemble(
    address: int, assembly: str, config: lief.assembly.AssemblerConfig = ...
) -> bytes: ...
