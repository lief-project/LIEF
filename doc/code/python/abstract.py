import lief


def parse_forms() -> None:
    # lief-doc: parse-start
    target = lief.parse("/tmp/some.elf")

    target = lief.parse("/Users/demo/some.macho")

    target = lief.parse(r"C:\some.pe.exe")
    # lief-doc: parse-end
    _ = target


def upcast() -> None:
    # lief-doc: upcast-start
    target = lief.parse("some.elf")
    assert type(target) is lief.ELF.Binary

    abstract = target.abstract
    assert type(abstract) is lief.Binary
    # lief-doc: upcast-end
