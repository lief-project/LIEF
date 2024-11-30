from collections.abc import Sequence
import io
import os
from typing import Iterator, Optional, Union, overload

import lief


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

def android_version(vdex_version: int) -> lief.Android.ANDROID_VERSIONS: ...

@overload
def parse(filename: str) -> Optional[File]: ...

@overload
def parse(obj: Union[io.IOBase | os.PathLike], name: str = '') -> Optional[File]: ...

@overload
def version(file: str) -> int: ...

@overload
def version(raw: Sequence[int]) -> int: ...
