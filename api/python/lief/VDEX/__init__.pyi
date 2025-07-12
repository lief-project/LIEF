from collections.abc import Sequence
import io
import os
from typing import Iterator, Optional, Union, overload

import lief
import lief.Android
import lief.OAT


@overload
def parse(filename: str) -> Optional[File]: ...

@overload
def parse(obj: Union[str | io.IOBase | os.PathLike | bytes | list[int]], name: str = '') -> Optional[File]: ...

class File(lief.Object):
    @property
    def header(self) -> Header: ...

    @property
    def dex_files(self) -> lief.OAT.Binary.it_dex_files: ...

    @property
    def dex2dex_json_info(self) -> str: ...

    def __str__(self) -> str: ...

class Header(lief.Object):
    @property
    def magic(self) -> list[int]: ...

    @property
    def version(self) -> int: ...

    @property
    def nb_dex_files(self) -> int: ...

    @property
    def dex_size(self) -> int: ...

    @property
    def verifier_deps_size(self) -> int: ...

    @property
    def quickening_info_size(self) -> int: ...

    def __str__(self) -> str: ...

@overload
def version(file: str) -> int: ...

@overload
def version(raw: Sequence[int]) -> int: ...

def android_version(vdex_version: int) -> lief.Android.ANDROID_VERSIONS: ...
