import lief


def remove_import(pe: lief.PE.Binary) -> None:
    # lief-doc: remove-import-start
    pe: lief.PE.Binary

    pe.remove_import("kernel32.dll")

    config = lief.PE.Builder.config_t()
    config.imports = True

    pe.write("new.exe", config)
    # lief-doc: remove-import-end


def remove_import_entry(pe: lief.PE.Binary) -> None:
    # lief-doc: remove-import-entry-start
    pe: lief.PE.Binary

    kernel32 = pe.get_import("kernel32.dll")
    assert kernel32 is not None
    kernel32.remove_entry("IsDebuggerPresent")

    config = lief.PE.Builder.config_t()
    config.imports = True

    pe.write("new.exe", config)
    # lief-doc: remove-import-entry-end


def add_import(pe: lief.PE.Binary) -> None:
    # lief-doc: add-import-start
    pe: lief.PE.Binary

    stdio = pe.add_import("api-ms-win-crt-stdio-l1-1-0.dll")
    stdio.add_entry("puts")

    config = lief.PE.Builder.config_t()
    config.imports = True

    pe.write("new.exe", config)
    # lief-doc: add-import-end


def add_import_cbk(pe: lief.PE.Binary) -> None:
    # lief-doc: add-import-cbk-start
    pe: lief.PE.Binary

    def iat_resolution_cbk(
        pe: lief.PE.Binary, imp: lief.PE.Import, entry: lief.PE.ImportEntry, rva: int
    ):
        # Process
        return

    stdio = pe.add_import("api-ms-win-crt-stdio-l1-1-0.dll")
    stdio.add_entry("puts")

    config = lief.PE.Builder.config_t()
    config.imports = True
    config.resolved_iat_cbk = iat_resolution_cbk

    pe.write("new.exe", config)
    # lief-doc: add-import-cbk-end


def add_import_func(pe: lief.PE.Binary) -> None:
    # lief-doc: add-import-func-start
    pe: lief.PE.Binary

    kernel32 = pe.add_import("kernel32.dll")
    kernel32.add_entry("GetStartupInfoW")

    config = lief.PE.Builder.config_t()
    config.imports = True

    pe.write("new.exe", config)
    # lief-doc: add-import-func-end
