import pathlib

import lief


def sections(coff: lief.COFF.Binary) -> None:
    # lief-doc: sections-start
    coff: lief.COFF.Binary

    for section in coff.sections:
        print(section.name)
    # lief-doc: sections-end


def disassemble(coff: lief.COFF.Binary) -> None:
    # lief-doc: disassemble-start
    coff: lief.COFF.Binary

    for inst in coff.disassemble("?foo@@YAHHH@Z"):
        print(inst)

    # Using demangled representation
    for inst in coff.disassemble("int __cdecl bar(int, int)"):
        print(inst)
    # lief-doc: disassemble-end


def parse_forms() -> lief.COFF.Binary | None:
    # lief-doc: parse-start

    # Using a filepath as a string
    coff: lief.COFF.Binary | None = lief.COFF.parse("hello.obj")

    # Using a Path from pathlib
    coff: lief.COFF.Binary | None = lief.COFF.parse(
        pathlib.Path(r"C:\Users\romain\test.obj")
    )

    # Using an io object
    with open("/tmp/test.ob", "rb") as f:
        coff: lief.COFF.Binary | None = lief.COFF.parse(f)
    # lief-doc: parse-end
    return coff
