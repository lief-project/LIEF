import pathlib

import lief


def inspect(pe: lief.PE.Binary) -> None:
    # lief-doc: inspect-start
    pe: lief.PE.Binary

    print(pe.rich_header)
    print(pe.authentihash_md5.hex(":"))

    for section in pe.sections:
        print(section.name, len(section.content))
    # lief-doc: inspect-end


def add_section(pe: lief.PE.Binary) -> None:
    # lief-doc: add-section-start
    pe: lief.PE.Binary

    section = lief.PE.Section(".hello")
    section.content = [0xCC] * 0x100
    pe.add_section(section)

    pe.write("new.exe")
    # lief-doc: add-section-end


def parse_from_dump() -> None:
    # lief-doc: dump-start
    # 0x7ffd21b80000 is the (absolute) address at which the dump was mapped
    pe = lief.PE.parse_from_dump("module.dump", 0x7FFD21B80000)
    assert isinstance(pe, lief.PE.Binary)

    for imp in pe.imports:
        print(imp.name)
    # lief-doc: dump-end


def module_dump() -> None:
    # lief-doc: dump-runtime-start
    # Find the module to dump in the current process
    mod = lief.runtime.module_from_name("target.dll")
    assert isinstance(mod, lief.runtime.windows.Module)

    # Dump the module's memory into a file (the raw bytes are also returned) ...
    data: bytes = mod.dump("module.dump")

    # ... and parse it back using the same imagebase:
    pe = lief.PE.parse_from_dump(data, mod.imagebase)
    # lief-doc: dump-runtime-end
    assert isinstance(pe, lief.PE.Binary)


def advanced_parse_write() -> None:
    # lief-doc: advanced-start
    parser_config = lief.PE.ParserConfig()
    parser_config.parse_signature = False

    pe = lief.PE.parse("some.exe", parser_config)
    assert isinstance(pe, lief.PE.Binary)

    builder_config = lief.PE.Builder.config_t()
    builder_config.imports = True

    pe.write("new.exe", builder_config)
    # lief-doc: advanced-end


def write_bytes(pe: lief.PE.Binary) -> bytes:
    # lief-doc: write-bytes-start
    pe: lief.PE.Binary

    new_pe: bytes = pe.write_to_bytes()
    # lief-doc: write-bytes-end
    return new_pe


def authenticode() -> None:
    # lief-doc: authenticode-start
    pe = lief.PE.parse("signed.exe")
    assert isinstance(pe, lief.PE.Binary)

    for signature in pe.signatures:
        for crt in signature.certificates:
            print(crt)

    assert pe.verify_signature() == lief.PE.Signature.VERIFICATION_FLAGS.OK
    # lief-doc: authenticode-end


def parse_forms() -> lief.PE.Binary | None:
    # lief-doc: parse-start

    # Using filepath
    pe: lief.PE.Binary | None = lief.PE.parse(r"C:\Users\test.exe")

    # Using a Path from pathlib
    pe: lief.PE.Binary | None = lief.PE.parse(pathlib.Path(r"C:\Users\test.exe"))

    # Using an io object
    with open(r"C:\Users\test.exe", "rb") as f:
        pe: lief.PE.Binary | None = lief.PE.parse(f)
    # lief-doc: parse-end
    return pe
