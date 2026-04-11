import subprocess
from pathlib import Path
from typing import cast

import lief
from utils import chmod_exe, get_sample, is_apple_m1, parse_macho, sign


def process_crypt_and_hash(path: str, delta: int = 0):
    """
    Test on a regular Mach-O binary that contains rebase fixups
    """
    fat = lief.MachO.parse(path)
    assert fat is not None
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None

    assert target.has(lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS)

    dyld_chained = target.get(lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS)
    assert isinstance(dyld_chained, lief.MachO.DyldChainedFixups)
    assert len(dyld_chained.payload) == dyld_chained.data_size

    assert dyld_chained.fixups_version == 0
    assert dyld_chained.starts_offset == 32
    assert dyld_chained.imports_offset == 112
    assert dyld_chained.symbols_offset == 272
    assert dyld_chained.imports_count == 40
    assert dyld_chained.imports_format == lief.MachO.DYLD_CHAINED_FORMAT.IMPORT

    assert len(dyld_chained.chained_starts_in_segments) == 5
    assert len(dyld_chained.bindings) == 41

    start_in_segment = dyld_chained.chained_starts_in_segments[2]
    assert start_in_segment.offset == 24
    assert start_in_segment.size == 26
    assert start_in_segment.page_size == 0x4000
    assert start_in_segment.segment_offset == 0x64000 + delta
    assert (
        start_in_segment.pointer_format
        == lief.MachO.DYLD_CHAINED_PTR_FORMAT.PTR_64_OFFSET
    )
    assert start_in_segment.max_valid_pointer == 0
    assert start_in_segment.page_count == 2
    seg0 = start_in_segment.segment
    assert seg0 is not None
    assert seg0.name == "__DATA_CONST"
    assert start_in_segment.page_start[0] == 0
    assert start_in_segment.page_start[1] == 16

    rebases = seg0.relocations
    assert len(rebases) == 1247
    assert (rebases[0].address, rebases[0].target) == (  # type: ignore
        0x100064150 + delta,
        0x100048D5E + delta,
    )
    assert (rebases[1246].address, rebases[1246].target) == (  # type: ignore
        0x10006B368 + delta,
        0x10006A190 + delta,
    )
    assert (rebases[389].address, rebases[389].target) == (  # type: ignore
        0x100066000 + delta,
        0x10005BA38 + delta,
    )

    start_in_segment = dyld_chained.chained_starts_in_segments[3]

    seg3 = start_in_segment.segment
    assert seg3 is not None
    rebases = seg3.relocations
    assert len(rebases) == 15

    assert (rebases[0].address, rebases[0].target) == (  # type: ignore
        0x10006C000 + delta,
        0x100054BB0 + delta,
    )
    assert (rebases[14].address, rebases[14].target) == (  # type: ignore
        0x10006C078 + delta,
        0x10004BF03 + delta,
    )


def test_1():
    """
    Simple test on the regular id binary comming from an Apple M1
    This sample does not contains rebase fixups
    """
    fat = parse_macho(
        "MachO/8119b2bd6a15b78b5c0bc2245eb63673173cb8fe9e0638f19aea7e68da668696_id.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None

    assert target.has(lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS)

    dyld_chained = target.get(lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS)
    assert isinstance(dyld_chained, lief.MachO.DyldChainedFixups)
    assert dyld_chained.fixups_version == 0
    assert dyld_chained.starts_offset == 32
    assert dyld_chained.imports_offset == 80
    assert dyld_chained.symbols_offset == 192
    assert dyld_chained.imports_count == 28
    assert dyld_chained.imports_format == lief.MachO.DYLD_CHAINED_FORMAT.IMPORT

    assert len(dyld_chained.chained_starts_in_segments) == 5
    assert len(dyld_chained.bindings) == 28

    start_in_segment: lief.MachO.DyldChainedFixups.chained_starts_in_segment = (
        dyld_chained.chained_starts_in_segments[2]
    )
    assert start_in_segment.offset == 24
    assert start_in_segment.segment_offset == 0x4000
    assert start_in_segment.size == 24
    assert start_in_segment.page_size == 0x4000
    assert (
        start_in_segment.pointer_format
        == lief.MachO.DYLD_CHAINED_PTR_FORMAT.PTR_ARM64E_USERLAND24
    )
    assert start_in_segment.max_valid_pointer == 0
    assert start_in_segment.page_count == 1
    seg1 = start_in_segment.segment
    assert seg1 is not None
    assert seg1.name == "__DATA_CONST"
    assert start_in_segment.page_start[0] == 0

    assert len(seg1.relocations) == 0

    bindings = dyld_chained.bindings
    assert len(bindings) == 28

    bnd_0 = bindings[0]
    assert bnd_0.offset == 0x4000
    assert bnd_0.format == lief.MachO.DYLD_CHAINED_FORMAT.IMPORT
    assert bnd_0.ptr_format == lief.MachO.DYLD_CHAINED_PTR_FORMAT.PTR_ARM64E_USERLAND24
    assert bnd_0.symbol is not None
    assert bnd_0.symbol.name == "_err"
    assert bnd_0.segment is not None
    assert bnd_0.segment.name == "__DATA_CONST"
    assert bnd_0.library is not None
    assert bnd_0.library.name == "/usr/lib/libSystem.B.dylib"
    assert bnd_0.address == 0x100004000
    assert bnd_0.sign_extended_addend == 0
    assert not bnd_0.weak_import

    bnd_14 = bindings[14]
    assert bnd_14.offset == 0x4070
    assert bnd_14.format == lief.MachO.DYLD_CHAINED_FORMAT.IMPORT
    assert bnd_14.ptr_format == lief.MachO.DYLD_CHAINED_PTR_FORMAT.PTR_ARM64E_USERLAND24
    assert bnd_14.symbol is not None
    assert bnd_14.symbol.name == "_getopt"
    assert bnd_14.segment is not None
    assert bnd_14.segment.name == "__DATA_CONST"
    assert bnd_14.library is not None
    assert bnd_14.library.name == "/usr/lib/libSystem.B.dylib"
    assert bnd_14.address == 0x100004070
    assert not bnd_14.weak_import
    assert bnd_14.sign_extended_addend == 0

    bnd_27 = bindings[27]
    assert bnd_27.offset == 0x40D8
    assert bnd_27.format == lief.MachO.DYLD_CHAINED_FORMAT.IMPORT
    assert bnd_27.ptr_format == lief.MachO.DYLD_CHAINED_PTR_FORMAT.PTR_ARM64E_USERLAND24
    assert bnd_27.symbol is not None
    assert bnd_27.symbol.name == "_optind"
    assert bnd_27.segment is not None
    assert bnd_27.segment.name == "__DATA_CONST"
    assert bnd_27.library is not None
    assert bnd_27.library.name == "/usr/lib/libSystem.B.dylib"
    assert bnd_27.address == 0x1000040D8
    assert not bnd_27.weak_import
    assert bnd_27.sign_extended_addend == 0


def test_2():
    process_crypt_and_hash(
        get_sample(
            "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
        )
    )


def test_3():
    """
    Test on dyld which contains DYLD_CHAINED_PTR_FORMAT.PTR_32
    """

    fat = parse_macho(
        "MachO/42d4f6b799d5d3ff88c50d4c6966773d269d19793226724b5e893212091bf737_dyld.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.X86)
    assert target is not None

    assert target.has(lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS)

    dyld_chained = cast(
        lief.MachO.DyldChainedFixups,
        target.get(lief.MachO.LoadCommand.TYPE.DYLD_CHAINED_FIXUPS),
    )
    assert dyld_chained.fixups_version == 0
    assert dyld_chained.starts_offset == 32
    assert dyld_chained.imports_offset == 616
    assert dyld_chained.symbols_offset == 616
    assert dyld_chained.imports_count == 0
    assert dyld_chained.imports_format == lief.MachO.DYLD_CHAINED_FORMAT.IMPORT
    assert dyld_chained.symbols_format == 0

    assert len(dyld_chained.chained_starts_in_segments) == 4
    assert len(dyld_chained.bindings) == 0

    start_in_segment = dyld_chained.chained_starts_in_segments[1]
    assert start_in_segment.offset == 24
    assert start_in_segment.size == 278
    assert start_in_segment.page_size == 0x4000
    assert start_in_segment.segment_offset == 0x58000
    assert start_in_segment.pointer_format == lief.MachO.DYLD_CHAINED_PTR_FORMAT.PTR_32
    assert start_in_segment.max_valid_pointer == 0x100000
    assert start_in_segment.page_count == 1
    seg = start_in_segment.segment
    assert seg is not None
    assert seg.name == "__DATA_CONST"
    assert start_in_segment.page_start[0] == 228
    rebases = seg.relocations
    assert len(rebases) == 952

    start_in_segment = dyld_chained.chained_starts_in_segments[2]
    assert start_in_segment.offset == 304
    assert start_in_segment.size == 278
    assert start_in_segment.page_size == 0x4000
    assert start_in_segment.segment_offset == 0x6C000
    assert start_in_segment.pointer_format == lief.MachO.DYLD_CHAINED_PTR_FORMAT.PTR_32
    assert start_in_segment.max_valid_pointer == 0x100000
    assert start_in_segment.page_count == 1
    seg = start_in_segment.segment
    assert seg is not None
    assert seg.name == "__DATA"
    assert start_in_segment.page_start[0] == 32769
    rebases = seg.relocations
    assert len(rebases) == 33

    assert (rebases[0].address, rebases[0].target) == (0x6C000, 0x45428)  # type: ignore[attr-defined]  # type: ignore
    assert (rebases[23].address, rebases[23].target) == (0x6C05C, 0)  # type: ignore[attr-defined]  # type: ignore
    assert (rebases[32].address, rebases[32].target) == (0x6C208, 0x4EEF9)  # type: ignore[attr-defined]  # type: ignore


def test_builder(tmp_path: Path):
    binary_name = "crypt_and_hash"
    fat = parse_macho(
        "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None
    output = tmp_path / f"{binary_name}.built"
    target.write(output)

    process_crypt_and_hash(str(output))

    if is_apple_m1():
        chmod_exe(output)
        sign(str(output))
        with subprocess.Popen(
            [str(output)],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            assert "CAMELLIA-256-CCM*-NO-TAG" in stdout
            assert "AES-128-CCM*-NO-TAG" in stdout


def test_linkedit_shift(tmp_path: Path):
    binary_name = "crypt_and_hash"
    fat = parse_macho(
        "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None

    # Shift content
    target.shift_linkedit(0x4000)

    output = f"{tmp_path}/{binary_name}.built"
    target.remove_signature()
    target.write(output)

    process_crypt_and_hash(output)

    if is_apple_m1():
        chmod_exe(output)
        sign(output)
        with subprocess.Popen(
            [output],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            assert "CAMELLIA-256-CCM*-NO-TAG" in stdout
            assert "AES-128-CCM*-NO-TAG" in stdout


def test_shift(tmp_path: Path):
    DELTA = 0x4000
    binary_name = "crypt_and_hash"
    fat = parse_macho(
        "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None

    target.shift(DELTA)

    output = f"{tmp_path}/{binary_name}.built"
    target.write(output)

    process_crypt_and_hash(output, DELTA)

    if is_apple_m1():
        chmod_exe(output)
        sign(output)
        with subprocess.Popen(
            [output],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            assert "CAMELLIA-256-CCM*-NO-TAG" in stdout
            assert "AES-128-CCM*-NO-TAG" in stdout


def test_issue_804(tmp_path: Path):
    fat = parse_macho("MachO/test_issue_804.bin")
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None
    dyld_fixups = target.dyld_chained_fixups
    assert dyld_fixups is not None
    bindings = dyld_fixups.bindings

    assert len(bindings) == 5

    objc_nsobj = set(
        binding.address
        for binding in bindings
        if binding.symbol is not None
        and binding.symbol.name == "_OBJC_METACLASS_$_NSObject"
    )
    assert objc_nsobj == {0x0100008090, 0x0100008098}

    output = f"{tmp_path}/test_issue_804.built"
    target.write(output)

    fat = lief.MachO.parse(output)
    assert fat is not None
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None
    dyld_fixups = target.dyld_chained_fixups
    assert dyld_fixups is not None
    bindings = dyld_fixups.bindings

    assert len(bindings) == 5

    objc_nsobj = set(
        binding.address
        for binding in bindings
        if binding.symbol is not None
        and binding.symbol.name == "_OBJC_METACLASS_$_NSObject"
    )
    assert objc_nsobj == {0x0100008090, 0x0100008098}

    if is_apple_m1():
        chmod_exe(output)
        sign(output)
        with subprocess.Popen(
            [output],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            _stdout = proc.stdout.read()


def test_issue_853(tmp_path: Path):
    ios14 = parse_macho("MachO/issue_853_classes_14.bin").at(0)
    assert ios14 is not None

    relocations = ios14.relocations
    assert len(relocations) == 31
    assert all(
        0 < (r.target - ios14.imagebase)  # type: ignore
        and (r.target - ios14.imagebase) < ios14.imagebase  # type: ignore
        for r in relocations
    )

    output = f"{tmp_path}/test_issue_853_ios14.bin"
    ios14.write(output)

    ios14_built = lief.parse(output)
    assert isinstance(ios14_built, lief.MachO.Binary)
    assert len(ios14_built.relocations) == 31
    assert ios14_built.relocations[0].target == 0x100007EA8  # type: ignore
    assert ios14_built.relocations[0].next == 4  # type: ignore

    ios15 = parse_macho("MachO/issue_853_classes_15.bin").at(0)
    assert ios15 is not None

    relocations = ios15.relocations
    assert len(relocations) == 31
    assert all(
        0 < (r.target - ios15.imagebase)  # type: ignore
        and (r.target - ios15.imagebase) < ios15.imagebase  # type: ignore
        for r in relocations
    )

    output = f"{tmp_path}/test_issue_853_ios15.bin"
    ios15.write(output)

    ios15_built = lief.parse(output)
    assert isinstance(ios15_built, lief.MachO.Binary)
    assert len(ios15_built.relocations) == 31
    assert ios15_built.relocations[0].target == 0x100007EA8  # type: ignore
    assert ios15_built.relocations[0].next == 4  # type: ignore


def test_with_imagebase():
    macho = parse_macho("MachO/liblog_srp_fixups.dylib").at(0)
    assert macho is not None
    chained = macho.dyld_chained_fixups
    assert chained is not None

    bindings = chained.bindings
    assert len(bindings) == 2

    assert bindings[0].symbol is not None
    assert bindings[0].symbol.name == "_calloc"
    assert bindings[0].address == 0x24150F758

    assert bindings[1].symbol is not None
    assert bindings[1].symbol.name == "_dlopen"
    assert bindings[1].address == 0x24150F778
