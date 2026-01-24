from typing import Iterator, Optional, Union

import lief.PE


class UnpackedFunction(lief.PE.RuntimeFunctionAArch64):
    class epilog_scope_t:
        start_offset: int

        start_index: int

        reserved: int

    class it_epilog_scopes:
        def __getitem__(self, arg: int, /) -> UnpackedFunction.epilog_scope_t: ...

        def __len__(self) -> int: ...

        def __iter__(self) -> UnpackedFunction.it_epilog_scopes: ...

        def __next__(self) -> UnpackedFunction.epilog_scope_t: ...

    xdata_rva: int

    version: int

    X: int

    E: int

    @property
    def epilog_count(self) -> int: ...

    @property
    def epilog_offset(self) -> int: ...

    code_words: int

    exception_handler: int

    unwind_code: memoryview

    @property
    def epilog_scopes(self) -> UnpackedFunction.it_epilog_scopes: ...

    @property
    def is_extended(self) -> bool: ...

class PackedFunction(lief.PE.RuntimeFunctionAArch64):
    frame_size: int

    reg_I: int

    reg_F: int

    H: int

    CR: int
