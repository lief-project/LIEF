import lief


def elf_parse() -> None:
    # lief-doc: elf-parse-start
    binary = lief.parse("/bin/ls")
    # lief-doc: elf-parse-end
    _ = binary


def elf_header(binary: lief.ELF.Binary) -> lief.ELF.Header:
    # lief-doc: elf-header-start
    binary: lief.ELF.Binary

    header = binary.header
    # lief-doc: elf-header-end
    return header


def elf_change_header(header: lief.ELF.Header) -> None:
    # lief-doc: elf-change-header-start
    header: lief.ELF.Header

    header.entrypoint = 0x123
    header.machine_type = lief.ELF.ARCH.AARCH64
    # lief-doc: elf-change-header-end


def elf_write(binary: lief.ELF.Binary) -> None:
    # lief-doc: elf-write-start
    binary: lief.ELF.Binary

    binary.write("ls.modified")
    # lief-doc: elf-write-end


def elf_sections(binary: lief.ELF.Binary) -> None:
    # lief-doc: elf-sections-start
    binary: lief.ELF.Binary

    for section in binary.sections:
        print(section.name)  # section name
        print(section.size)  # section size
        print(len(section.content))  # Should match the previous print
    # lief-doc: elf-sections-end


def elf_text(binary: lief.ELF.Binary) -> None:
    # lief-doc: elf-text-start
    binary: lief.ELF.Binary

    text = binary.get_section(".text")
    assert text is not None
    text.content = bytes([0x33] * text.size)
    # lief-doc: elf-text-end


def pe_parse() -> None:
    # lief-doc: pe-parse-start
    binary = lief.parse("C:\\Windows\\explorer.exe")
    # lief-doc: pe-parse-end
    _ = binary


def pe_headers(binary: lief.PE.Binary) -> None:
    # lief-doc: pe-headers-start
    binary: lief.PE.Binary

    print(binary.dos_header)
    print(binary.header)
    print(binary.optional_header)
    # lief-doc: pe-headers-end


def pe_imports(binary: lief.PE.Binary) -> None:
    # lief-doc: pe-imports-start
    # Using the abstract layer
    binary: lief.PE.Binary

    for func in binary.imported_functions:
        print(func)

    # Using the PE definition
    for func in binary.imports:
        print(func)
    # lief-doc: pe-imports-end


def pe_imports_detailed(binary: lief.PE.Binary) -> None:
    # lief-doc: pe-imports-detailed-start
    binary: lief.PE.Binary

    for imported_library in binary.imports:
        print("Library name: " + imported_library.name)
        for func in imported_library.entries:
            if not func.is_ordinal:
                print(func.name)
            print(func.iat_address)
    # lief-doc: pe-imports-detailed-end
