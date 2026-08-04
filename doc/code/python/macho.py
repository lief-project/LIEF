import pathlib

import lief


def iterate(fat: lief.MachO.FatBinary) -> lief.MachO.Binary | None:
    # lief-doc: iterate-start
    fat: lief.MachO.FatBinary

    # Iterate
    for macho in fat:
        print(macho.entrypoint)
        print(len(macho.commands))

    # Pick one at the specified index
    macho = fat.at(0)

    # Pick one based on the architecture
    macho = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    # lief-doc: iterate-end
    return macho


def write_bytes(macho: lief.MachO.Binary) -> bytes:
    # lief-doc: write-bytes-start
    macho: lief.MachO.Binary

    new_macho: bytes = macho.write_to_bytes()
    # lief-doc: write-bytes-end
    return new_macho


def parse_from_dump() -> None:
    # lief-doc: dump-start
    # 0x11e32c000 is the (absolute) address at which the dump was mapped
    fat = lief.MachO.parse_from_dump("module.dump", 0x11E32C000)
    assert isinstance(fat, lief.MachO.FatBinary)

    macho = fat.at(0)
    assert isinstance(fat, lief.MachO.Binary)

    for segment in macho.segments:
        print(segment.name, hex(segment.virtual_address))
    # lief-doc: dump-end


def module_dump() -> None:
    # lief-doc: dump-runtime-start
    # Find the module to dump in the current process
    mod = lief.runtime.module_from_name("libsystem_c.dylib")
    assert isinstance(mod, lief.runtime.osx.Module)

    # Dump the module's memory into a file (the raw bytes are also returned) ...
    data: bytes = mod.dump("module.dump")

    # ... and parse it back using the same imagebase:
    macho = lief.MachO.parse_from_dump(data, mod.imagebase)
    # lief-doc: dump-runtime-end
    assert isinstance(macho, lief.MachO.FatBinary)


def rpath_atrpath(macho: lief.MachO.Binary) -> None:
    # lief-doc: rpath-atrpath-start
    macho: lief.MachO.Binary

    lib = macho.find_library("libmylib.dylib")
    assert isinstance(lib, lief.MachO.DylibCommand)

    lib.name = "@rpath/libmylib.dylib"

    macho.write("hello_fixed.bin")
    # lief-doc: rpath-atrpath-end


def parse_forms() -> lief.MachO.FatBinary | None:
    # lief-doc: parse-start

    # Using filepath
    macho: lief.MachO.FatBinary | None = lief.MachO.parse("/bin/ls")

    # Using a Path from pathlib
    macho: lief.MachO.FatBinary | None = lief.MachO.parse(
        pathlib.Path(r"C:\Users\test.macho")
    )

    # Using an io object
    with open("/bin/ssh", "rb") as f:
        macho: lief.MachO.FatBinary | None = lief.MachO.parse(f)
    # lief-doc: parse-end
    return macho


def write_fat(macho: lief.MachO.FatBinary) -> None:
    # lief-doc: write-fat-start
    macho: lief.MachO.FatBinary

    macho.at(0).write("fit.macho")
    macho.write("fat.macho")  # write-back the whole FAT binary
    # lief-doc: write-fat-end


def advanced_parse_write() -> None:
    # lief-doc: advanced-start
    parser_config = lief.MachO.ParserConfig()
    parser_config.parse_dyld_bindings = False

    fat = lief.MachO.parse("my.macho", parser_config)
    assert isinstance(fat, lief.MachO.FatBinary)

    macho = fat.at(0)
    assert isinstance(fat, lief.MachO.Binary)

    builder_config = lief.MachO.Builder.config_t()
    builder_config.linkedit = False

    macho.write("new.macho", builder_config)
    # lief-doc: advanced-end


def rpath_change_lib() -> None:
    # lief-doc: rpath-change-lib-start
    fat = lief.MachO.parse("hello.bin")
    assert isinstance(fat, lief.MachO.FatBinary)

    macho = fat.at(0)
    assert isinstance(fat, lief.MachO.Binary)

    lib = macho.find_library("libmylib.dylib")
    assert isinstance(lib, lief.MachO.DylibCommand)

    lib.name = "/opt/homebrew/my_package/libmylib.dylib"

    macho.write("hello_fixed.bin")
    # lief-doc: rpath-change-lib-end


def rpath_add() -> None:
    # lief-doc: rpath-add-start
    fat = lief.MachO.parse("hello.bin")
    assert isinstance(fat, lief.MachO.FatBinary)

    macho = fat.at(0)
    assert isinstance(fat, lief.MachO.Binary)

    rpath = lief.MachO.RPathCommand.create("/opt/homebrew/my_package")
    assert isinstance(rpath, lief.MachO.RPathCommand)

    macho.add(rpath)
    # lief-doc: rpath-add-end


def parse_config() -> None:
    # lief-doc: parse-config-start
    fatbinary_1 = lief.MachO.parse("/usr/bin/ls", config=lief.MachO.ParserConfig.deep)
    # or
    fatbinary_2 = lief.MachO.parse("/usr/bin/ls", config=lief.MachO.ParserConfig.quick)
    # lief-doc: parse-config-end
    _ = (fatbinary_1, fatbinary_2)
