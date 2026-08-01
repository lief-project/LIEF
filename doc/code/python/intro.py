import lief


def intro() -> None:
    # lief-doc: intro-start

    elf: lief.ELF.Binary | None = lief.ELF.parse("libc.so")
    assert elf is not None

    for symbol in elf.symbols:
        print(symbol.address, symbol.name)

    print(elf.header)

    for entry in elf.dynamic_entries:
        if isinstance(entry, lief.ELF.DynamicEntryLibrary):
            entry.name = "libhello.so"

    elf.write("modified.elf")
    # lief-doc: intro-end
