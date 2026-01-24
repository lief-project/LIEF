from collections.abc import Sequence
import enum
import io
import os
from typing import Iterator, Optional, Union, overload

import lief
import lief.Android


class STORAGE_MODES(enum.Enum):
    UNCOMPRESSED = 0

    LZ4 = 1

    LZ4HC = 2

@overload
def parse(filename: str) -> Optional[File]: ...

@overload
def parse(raw: Sequence[int], name: str = '') -> Optional[File]: ...

@overload
def parse(obj: Union[str | io.IOBase | os.PathLike | bytes | list[int]], name: str = '') -> Optional[File]: ...

class File(lief.Object):
    @property
    def header(self) -> Header: ...

    def __str__(self) -> str: ...

class Header(lief.Object):
    @property
    def magic(self) -> list[int]: ...

    @property
    def version(self) -> int: ...

    @property
    def image_begin(self) -> int: ...

    @property
    def image_size(self) -> int: ...

    @property
    def oat_checksum(self) -> int: ...

    @property
    def oat_file_begin(self) -> int: ...

    @property
    def oat_file_end(self) -> int: ...

    @property
    def oat_data_end(self) -> int: ...

    @property
    def patch_delta(self) -> int: ...

    @property
    def image_roots(self) -> int: ...

    @property
    def pointer_size(self) -> int: ...

    @property
    def compile_pic(self) -> bool: ...

    @property
    def nb_sections(self) -> int: ...

    @property
    def nb_methods(self) -> int: ...

    @property
    def boot_image_begin(self) -> int: ...

    @property
    def boot_image_size(self) -> int: ...

    @property
    def boot_oat_begin(self) -> int: ...

    @property
    def boot_oat_size(self) -> int: ...

    @property
    def storage_mode(self) -> STORAGE_MODES: ...

    @property
    def data_size(self) -> int: ...

    def __str__(self) -> str: ...

@overload
def version(file: str) -> int: ...

@overload
def version(raw: Sequence[int]) -> int: ...

def android_version(art_version: int) -> lief.Android.ANDROID_VERSIONS: ...
