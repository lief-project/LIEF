from pathlib import Path

import lief
import pytest
from utils import check_layout, get_sample, parse_macho


def test_func_variants(tmp_path: Path):
    def check_variant(variant: lief.MachO.FunctionVariants):
        runtime_table = variant.runtime_table
        assert len(runtime_table) == 2

        assert (
            runtime_table[0].kind
            == lief.MachO.FunctionVariants.RuntimeTable.KIND.X86_64
        )
        assert runtime_table[0].offset == 16
        assert len(runtime_table[0].entries) == 3

        assert runtime_table[0].entries[0].impl == 0x0000056C
        assert runtime_table[0].entries[0].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_ROSETTA,
        ]
        assert runtime_table[0].entries[1].impl == 0x00000590

        assert runtime_table[0].entries[1].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_HASWELL,
        ]
        assert runtime_table[0].entries[2].impl == 0x000005B4

        assert runtime_table[0].entries[2].flags == []

        assert (
            runtime_table[1].kind
            == lief.MachO.FunctionVariants.RuntimeTable.KIND.X86_64
        )
        assert runtime_table[1].offset == 48
        assert len(runtime_table[1].entries) == 3

        assert runtime_table[1].entries[0].impl == 0x000005D8
        assert runtime_table[1].entries[0].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_ROSETTA,
        ]
        assert runtime_table[1].entries[1].impl == 0x000005E0

        assert runtime_table[1].entries[1].flags == [
            lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS.X86_64_HASWELL,
        ]
        assert runtime_table[1].entries[2].impl == 0x000005E8

        assert runtime_table[1].entries[2].flags == []

    bin_path = Path(get_sample("MachO/variants_alt.dylib"))
    fat_parsed = lief.MachO.parse(bin_path)
    assert fat_parsed is not None
    macho = fat_parsed.at(0)
    assert macho is not None

    checked, err = lief.MachO.check_layout(macho)
    assert checked, err

    func_variants = macho.function_variants
    assert func_variants is not None
    raw_content = bytes(func_variants.content)
    assert (
        raw_content.hex()
        == "020000000c0000002c00000004000000030000006c050000080000009005000009000000b40"
        "50000000000000400000003000000d805000008000000e005000009000000e8050000000000"
        "0000000000"
    )

    check_variant(func_variants)

    output = tmp_path / bin_path.name
    macho.write(output)

    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    func_variants = new.function_variants
    assert func_variants is not None
    raw_content = bytes(func_variants.content)
    assert bytes(func_variants.content) == raw_content

    check_variant(func_variants)


def test_func_variants_modification(tmp_path: Path):
    FLAGS = lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS
    KIND = lief.MachO.FunctionVariants.RuntimeTable.KIND

    bin_path = Path(get_sample("MachO/variants_alt.dylib"))
    fat = lief.MachO.parse(bin_path)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None

    func_variants = macho.function_variants
    assert func_variants is not None

    assert func_variants.runtime_table[0].entries[0].impl == 0x0000056C
    assert not func_variants.runtime_table[0].entries[0].another_table

    func_variants.runtime_table[0].entries[0].impl = 0x11223344

    entry = func_variants.runtime_table[1].entries[0]
    entry.impl = 0x7FFFFFFF  # widest value that fits on 31 bits
    entry.another_table = True

    output = tmp_path / bin_path.name
    macho.write(output)

    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None

    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    new_fv = new.function_variants
    assert new_fv is not None
    assert len(new_fv.runtime_table) == 2

    table0 = new_fv.runtime_table[0]
    assert table0.kind == KIND.X86_64
    assert table0.entries[0].impl == 0x11223344
    assert not table0.entries[0].another_table
    assert table0.entries[1].impl == 0x00000590
    assert table0.entries[1].flags == [FLAGS.X86_64_HASWELL]
    assert table0.entries[2].impl == 0x000005B4
    assert table0.entries[2].flags == []

    table1 = new_fv.runtime_table[1]
    assert table1.kind == KIND.X86_64
    assert table1.entries[0].impl == 0x7FFFFFFF
    assert table1.entries[0].another_table
    assert table1.entries[1].impl == 0x000005E0
    assert table1.entries[2].impl == 0x000005E8


@pytest.mark.private
def test_function_variants(tmp_path: Path):
    FLAGS = lief.MachO.FunctionVariants.RuntimeTableEntry.FLAGS
    KIND = lief.MachO.FunctionVariants.RuntimeTable.KIND

    # The payload encodes a single runtime table holding two entries:
    #   01000000                            tableCount       = 1
    #   08000000                            tableOffsets[0]  = 8
    #   01000000                            kind             = PER_PROCESS (1)
    #   02000000                            count            = 2
    #   f4246900 02000000                   entry0: impl=0x6924f4 flags=[mte_enabled]
    #   ec246900 00000000                   entry1: impl=0x6924ec flags=[default]
    EXPECTED_CONTENT = (
        "01000000080000000100000002000000f424690002000000ec24690000000000"
    )

    def check_variant(variant: lief.MachO.FunctionVariants):
        # The payload size is stable across a round-trip while the offset is
        # not (it depends on the rebuilt __LINKEDIT layout).
        assert variant.data_size == 32
        assert bytes(variant.content).hex() == EXPECTED_CONTENT

        runtime_table = variant.runtime_table
        assert len(runtime_table) == 1

        table = runtime_table[0]
        assert table.kind == KIND.PER_PROCESS
        assert table.offset == 12
        assert len(table.entries) == 2

        # First entry: a dedicated implementation selected when the process
        # runs with Memory Tagging (MTE) enabled.
        mte = table.entries[0]
        assert mte.impl == 0x006924F4
        assert not mte.another_table
        assert bytes(mte.flag_bit_nums) == b"\x02\x00\x00\x00"
        assert mte.flags == [FLAGS.PER_PROCESS_MTE_ENABLED]
        assert str(mte) == "Function: 0x006924f4 02: mte_enabled"

        # Second entry: the default implementation (no flag set).
        default = table.entries[1]
        assert default.impl == 0x006924EC
        assert not default.another_table
        assert bytes(default.flag_bit_nums) == b"\x00\x00\x00\x00"
        assert default.flags == []
        assert str(default) == "Function: 0x006924ec 00: default"

        # to_string() of the aggregated objects
        assert "PER_PROCESS" in str(table)
        assert "FUNCTION_VARIANTS" in str(variant)

    macho = parse_macho("private/MachO/bluetoothd").take(
        lief.MachO.Header.CPU_TYPE.ARM64
    )
    assert macho is not None

    checked, err = lief.MachO.check_layout(macho)
    assert checked, err

    func_variants = macho.function_variants
    print(func_variants)
    assert func_variants is not None

    # On-disk offset of the payload within __LINKEDIT for the original binary.
    assert func_variants.data_offset == 0x00B5EA28

    check_variant(func_variants)

    # Round-trip
    output = tmp_path / "bluetoothd_arm64.bin"
    macho.write(output)

    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None

    check_layout(new)

    new_func_variants = new.function_variants
    assert new_func_variants is not None
    check_variant(new_func_variants)


def test_function_variant_fixups_api():
    Fixup = lief.MachO.FunctionVariantFixups.Fixup

    # Default-constructed fixup
    default = Fixup()
    assert default.seg_offset == 0
    assert default.seg_index == 0
    assert default.variant_index == 0
    assert not default.pac_auth
    assert not default.pac_address
    assert default.pac_key == 0
    assert default.pac_diversity == 0
    # A fixup that is not bound to a parsed binary has no resolved segment.
    assert default.segment is None

    # Field constructor
    fixup = Fixup(
        seg_offset=0x1234,
        seg_index=3,
        variant_index=7,
        pac_auth=True,
        pac_address=False,
        pac_key=2,
        pac_diversity=0xABCD,
    )
    assert fixup.seg_offset == 0x1234
    assert fixup.seg_index == 3
    assert fixup.variant_index == 7
    assert fixup.pac_auth
    assert not fixup.pac_address
    assert fixup.pac_key == 2
    assert fixup.pac_diversity == 0xABCD
    assert "PAC" in str(fixup)

    # Setters
    fixup.seg_offset = 0x10
    fixup.seg_index = 1
    fixup.variant_index = 9
    fixup.pac_auth = False
    fixup.pac_address = True
    fixup.pac_key = 1
    fixup.pac_diversity = 0
    assert fixup.seg_offset == 0x10
    assert fixup.seg_index == 1
    assert fixup.variant_index == 9
    assert not fixup.pac_auth
    assert fixup.pac_address
    assert fixup.pac_key == 1
    # No PAC info is printed once auth is disabled
    assert "PAC" not in str(fixup)


@pytest.mark.private
def test_function_variant_fixups(tmp_path: Path):
    EXPECTED_CONTENT = "484d050002300000"

    def check_fixups(fvf: lief.MachO.FunctionVariantFixups):
        assert fvf.data_size == 8
        assert bytes(fvf.content).hex() == EXPECTED_CONTENT

        fixups = fvf.fixups
        assert len(fixups) == 1

        fixup = fixups[0]
        assert fixup.seg_offset == 0x00054D48
        assert fixup.seg_index == 2
        assert fixup.variant_index == 0
        assert fixup.pac_auth
        assert fixup.pac_address
        assert fixup.pac_key == 0
        assert fixup.pac_diversity == 0

        assert fixup.segment is not None
        assert fixup.segment.name == "__DATA_CONST"

        assert "__DATA_CONST" in str(fixup)
        assert "key=IA" in str(fixup)
        assert "nb_fixups = 1" in str(fvf)
        assert "__DATA_CONST" in str(fvf)

    macho = parse_macho("private/MachO/bluetoothd").take(
        lief.MachO.Header.CPU_TYPE.ARM64
    )
    assert macho is not None

    checked, err = lief.MachO.check_layout(macho)
    assert checked, err

    fvf = macho.function_variant_fixups
    assert fvf is not None
    assert fvf.data_offset == 0x00B5EA48
    check_fixups(fvf)

    # Round-trip: re-writing the binary must faithfully commit the fixups.
    output = tmp_path / "bluetoothd_arm64.bin"
    macho.write(output)

    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    new_fvf = new.function_variant_fixups
    assert new_fvf is not None
    check_fixups(new_fvf)


@pytest.mark.private
def test_function_variant_fixups_modification(tmp_path: Path):
    macho = parse_macho("private/MachO/bluetoothd").take(
        lief.MachO.Header.CPU_TYPE.ARM64
    )
    assert macho is not None

    fvf = macho.function_variant_fixups
    assert fvf is not None
    assert len(fvf.fixups) == 1

    fvf.add(
        lief.MachO.FunctionVariantFixups.Fixup(
            seg_offset=0x40,
            seg_index=1,
            variant_index=0,
            pac_auth=False,
            pac_address=False,
            pac_key=0,
            pac_diversity=0,
        )
    )

    fixup = fvf.fixups[0]
    fixup.seg_offset = 0x1122
    fixup.pac_key = 3
    fixup.pac_diversity = 0x1234

    output = tmp_path / "bluetoothd_arm64.bin"
    macho.write(output)

    fat_new = lief.MachO.parse(output)
    assert fat_new is not None
    new = fat_new.at(0)
    assert new is not None
    checked, err = lief.MachO.check_layout(new)
    assert checked, err

    new_fvf = new.function_variant_fixups
    assert new_fvf is not None
    assert len(new_fvf.fixups) == 2

    first = new_fvf.fixups[0]
    assert first.seg_offset == 0x1122
    assert first.pac_key == 3
    assert first.pac_diversity == 0x1234
    # Untouched fields are preserved
    assert first.seg_index == 2
    assert first.variant_index == 0
    assert first.pac_auth
    assert first.pac_address

    second = new_fvf.fixups[1]
    assert second.seg_offset == 0x40
    assert second.seg_index == 1
    assert second.variant_index == 0
    assert not second.pac_auth


@pytest.mark.private
def test_function_variant_fixups_layout_check():
    def corrupt(mutate) -> str:
        macho = parse_macho("private/MachO/bluetoothd").take(
            lief.MachO.Header.CPU_TYPE.ARM64
        )
        assert macho is not None
        ok, _ = lief.MachO.check_layout(macho)
        assert ok
        fvf = macho.function_variant_fixups
        assert fvf is not None
        mutate(fvf.fixups[0])
        ok, err = lief.MachO.check_layout(macho)
        assert not ok
        return err

    def set_seg_index(f):
        f.seg_index = 14  # the binary only has 5 segments

    def set_variant(f):
        f.variant_index = 99  # the binary defines a single table

    def set_offset(f):
        f.seg_offset = 0xFFFFFFF0  # outside of __DATA_CONST

    assert "segment #14" in corrupt(set_seg_index)
    assert "function-variant table #99" in corrupt(set_variant)
    assert "outside of segment" in corrupt(set_offset)


@pytest.mark.private
def test_function_variant_shift(tmp_path: Path):
    # Inserting many load commands forces Binary::shift, which must relocate the
    # impl() offsets held by LC_FUNCTION_VARIANTS. impl() is an image-base
    # relative offset, so a correctly shifted impl() keeps pointing at a function
    # recorded in LC_FUNCTION_STARTS. That independently shifted table is used as
    # an oracle (here and in the layout checker) to prove impl() tracked the
    # shift: a stale offset stays mapped in __TEXT but no longer matches a
    # function start.
    macho = parse_macho("private/MachO/bluetoothd").take(
        lief.MachO.Header.CPU_TYPE.ARM64
    )
    assert macho is not None
    print(macho.function_variants)
    print(macho.function_variant_fixups)

    def variant_impls(m: lief.MachO.Binary) -> list[int]:
        fv = m.function_variants
        assert fv is not None
        return [
            entry.impl
            for table in fv.runtime_table
            for entry in table.entries
            if not entry.another_table
        ]

    def function_starts(m: lief.MachO.Binary) -> set[int]:
        fs = m.function_starts
        assert fs is not None
        return set(fs.functions)

    before_starts = function_starts(macho)
    before_impls = variant_impls(macho)
    assert before_impls  # the sample defines genuine function-variant impls
    assert all(impl in before_starts for impl in before_impls)

    for i in range(100):
        macho.add_library(f"libtest.{i}.dylib")

    output = tmp_path / "bluetoothd_arm64.bin"
    macho.write(output)

    new = parse_macho(output).at(0)
    assert new is not None
    check_layout(output)

    after_starts = function_starts(new)
    after_impls = variant_impls(new)

    # The load-command insertion shifted the code, so every impl() must have
    # moved accordingly and must still resolve to a recorded function start.
    assert after_impls != before_impls
    assert all(impl in after_starts for impl in after_impls)

    print(new.function_variants)
    print(new.function_variant_fixups)
