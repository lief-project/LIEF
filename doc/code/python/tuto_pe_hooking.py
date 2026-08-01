import lief


def disable_aslr(binary: lief.PE.Binary) -> None:
    # lief-doc: disable-aslr-start
    binary: lief.PE.Binary

    binary.optional_header.dll_characteristics &= (
        ~lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE
    )
    # lief-doc: disable-aslr-end


def disable_nx(binary: lief.PE.Binary) -> None:
    # lief-doc: disable-nx-start
    binary: lief.PE.Binary

    binary.optional_header.dll_characteristics &= (
        ~lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT
    )
    # lief-doc: disable-nx-end


def add_exitprocess(binary: lief.PE.Binary) -> None:
    # lief-doc: add-exitprocess-start
    binary: lief.PE.Binary

    kernel32 = binary.get_import("KERNEL32.dll")
    kernel32.add_entry("ExitProcess")
    # lief-doc: add-exitprocess-end
