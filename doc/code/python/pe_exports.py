import lief


def create_export_entries(pe: lief.PE.Binary) -> None:
    # lief-doc: create-entries-start
    pe: lief.PE.Binary

    exp = pe.get_export()
    assert isinstance(exp, lief.PE.Export)

    # Remove an entry
    exp.remove_entry("my_exported_name")

    # Add a new export
    exp.add_entry("fuzz_me", 0x10010)

    config = lief.PE.Builder.config_t()
    config.exports = True
    config.export_section = ".myedata"  # optional

    pe.write("out.dll", config)
    # lief-doc: create-entries-end


def convert_to_dll(pe: lief.PE.Binary) -> None:
    # lief-doc: dll-header-start
    pe: lief.PE.Binary

    pe.header.add_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    pe.optional_header.addressof_entrypoint = 0
    # lief-doc: dll-header-end


def create_export_table(pe: lief.PE.Binary) -> None:
    # lief-doc: create-table-start
    pe: lief.PE.Binary

    exp = lief.PE.Export(
        "lib_exe2dll.dll",
        [
            lief.PE.ExportEntry("cbk1", 0x0001000),
            lief.PE.ExportEntry("cbk2", 0x0001010),
        ],
    )

    pe.set_export(exp)

    config = lief.PE.Builder.config_t()
    config.exports = True

    pe.write("lib_exe2dll.dll")
    # lief-doc: create-table-end
