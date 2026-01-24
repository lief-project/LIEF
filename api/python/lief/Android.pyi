import enum
from typing import Iterator, Optional, Union


class ANDROID_VERSIONS(enum.Enum):
    @staticmethod
    def from_value(arg: int, /) -> ANDROID_VERSIONS: ...

    def __eq__(self, arg, /) -> bool: ...

    def __ne__(self, arg, /) -> bool: ...

    def __int__(self) -> int: ...

    UNKNOWN = 0

    VERSION_601 = 1

    VERSION_700 = 2

    VERSION_710 = 3

    VERSION_712 = 4

    VERSION_800 = 5

    VERSION_810 = 6

    VERSION_900 = 7

def code_name(version: ANDROID_VERSIONS) -> str: ...

def version_string(version: ANDROID_VERSIONS) -> str: ...
