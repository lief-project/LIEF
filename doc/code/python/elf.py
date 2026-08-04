import pathlib

import lief


def inspect(elf: lief.ELF.Binary) -> None:
    # lief-doc: inspect-start
    elf: lief.ELF.Binary

    print(elf.header.entrypoint)

    for section in elf.sections:
        print(section.name, len(section.content))
    # lief-doc: inspect-end


def modify_write(elf: lief.ELF.Binary) -> None:
    # lief-doc: write-start
    elf: lief.ELF.Binary

    elf.add_library("libdemo.so")
    elf.write("new.elf")
    # lief-doc: write-end


def write_bytes(elf: lief.ELF.Binary) -> bytes:
    # lief-doc: write-bytes-start
    elf: lief.ELF.Binary

    new_elf: bytes = elf.write_to_bytes()
    # lief-doc: write-bytes-end
    return new_elf


def add_loaded_segment(elf: lief.ELF.Binary) -> lief.ELF.Segment | None:
    # lief-doc: add-segment-start
    elf: lief.ELF.Binary

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPES.LOAD
    segment.content = list(b"Hello World")

    new_segment = elf.add(segment)

    elf.write("new.elf")
    # lief-doc: add-segment-end
    return new_segment


def add_loaded_section(elf: lief.ELF.Binary) -> lief.ELF.Section | None:
    # lief-doc: add-section-loaded-start
    elf: lief.ELF.Binary

    section = lief.ELF.Section(".lief_demo")
    section.content = list(b"Hello World")

    new_section = elf.add(section, loaded=True)

    elf.write("new.elf")
    # lief-doc: add-section-loaded-end
    return new_section


def add_unloaded_section(elf: lief.ELF.Binary) -> lief.ELF.Section | None:
    # lief-doc: add-section-unloaded-start
    elf: lief.ELF.Binary

    section = lief.ELF.Section(".metadata")
    section.content = list(b"version: 1.2.3")

    # /!\ Note that loaded is set to False here
    # ------------------------------------------
    new_section = elf.add(section, loaded=False)

    elf.write("new.elf")
    # lief-doc: add-section-unloaded-end
    return new_section


def parse_from_dump() -> None:
    # lief-doc: dump-start
    # 0x7f9b98e00000 is the (absolute) address at which the dump was mapped
    elf = lief.ELF.parse_from_dump("module.dump", 0x7F9B98E00000)
    assert elf is not None

    for segment in elf.segments:
        print(segment.type, hex(segment.virtual_address))
    # lief-doc: dump-end


def module_dump() -> None:
    # lief-doc: dump-runtime-start
    # Find the module to dump in the current process
    mod = lief.runtime.module_from_name("libc.so.6")
    assert mod is not None

    # Dump the module's memory into a file (the raw bytes are also returned)
    data: bytes = mod.dump("module.dump")

    # and parse it back using the same imagebase:
    elf = lief.ELF.parse_from_dump(data, mod.imagebase)
    # lief-doc: dump-runtime-end
    assert elf is not None


def advanced_parse_write() -> None:
    # lief-doc: advanced-start
    parser_config = lief.ELF.ParserConfig()
    parser_config.parse_overlay = False

    elf = lief.ELF.parse("my.elf", parser_config)
    assert isinstance(elf, lief.ELF.Binary)

    builder_config = lief.ELF.Builder.config_t()
    builder_config.gnu_hash = False

    elf.write("new.elf", builder_config)
    # lief-doc: advanced-end


def rpath_add(elf: lief.ELF.Binary) -> None:
    # lief-doc: rpath-add-start
    elf: lief.ELF.Binary

    runpath = lief.ELF.DynamicEntryRunPath("$ORIGIN:/opt/lib64")

    elf.add(runpath)

    other_runpath = lief.ELF.DynamicEntryRunPath(["$ORIGIN", "/opt/lib64"])

    elf.add(other_runpath)

    elf.write("updated.elf")
    # lief-doc: rpath-add-end


def rpath_change(elf: lief.ELF.Binary) -> None:
    # lief-doc: rpath-change-start
    elf: lief.ELF.Binary

    runpath = elf.get(lief.ELF.DynamicEntry.TAG.RUNPATH)
    assert runpath is not None

    runpath.runpath = "$ORIGIN:/opt/lib64"
    runpath.append("lib-x86_64-gnu")

    elf.write("updated.elf")
    # lief-doc: rpath-change-end


def rpath_remove(elf: lief.ELF.Binary) -> None:
    # lief-doc: rpath-remove-start
    elf: lief.ELF.Binary

    # Remove **all** DT_RUNPATH entries
    elf.remove(lief.ELF.DynamicEntry.TAG.RUNPATH)

    # Remove all entries that contain '$ORIGIN'
    to_remove: list[lief.ELF.DynamicEntryRunPath] = []
    for dt_entry in elf.dynamic_entries:
        if not isinstance(dt_entry, lief.ELF.DynamicEntryRunPath):
            continue

        if "$ORIGIN" in dt_entry.runpath:
            to_remove.append(dt_entry)

    for entry in to_remove:
        elf.remove(entry)

    elf.write("updated.elf")
    # lief-doc: rpath-remove-end


def symver_remove_symbol(elf: lief.ELF.Binary) -> None:
    # lief-doc: symver-symbol-start
    elf: lief.ELF.Binary

    sym = elf.get_dynamic_symbol("printf")
    assert sym is not None and sym.symbol_version is not None

    sym.symbol_version.as_global()

    elf.write("updated.elf")
    # lief-doc: symver-symbol-end


def symver_remove_library(elf: lief.ELF.Binary) -> None:
    # lief-doc: symver-library-start
    elf: lief.ELF.Binary

    elf.remove_version_requirement("libm.so.6")

    elf.write("updated.elf")
    # lief-doc: symver-library-end


def parse_forms() -> lief.ELF.Binary | None:
    # lief-doc: parse-start

    # Using filepath
    elf: lief.ELF.Binary | None = lief.ELF.parse("/bin/ls")

    # Using a Path from pathlib
    elf: lief.ELF.Binary | None = lief.ELF.parse(pathlib.Path(r"C:\Users\test.elf"))

    # Using an io object
    with open("/bin/ssh", "rb") as f:
        elf: lief.ELF.Binary | None = lief.ELF.parse(f)
    # lief-doc: parse-end
    return elf
