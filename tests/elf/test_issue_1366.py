from pathlib import Path

import lief
import pytest
from utils import check_layout, parse_elf

NEW_INTERPRETER = "/root/lief/ld-linux-aarch64.so.1"

RUNPATH = "${ORIGIN}:${ORIGIN}/../dep"


def _assert_page_compatible(elf: lief.ELF.Binary, pagesize: int):
    """
    Check that the PT_LOAD segments of the given binary can be mapped
    independently on a system whose page size is `pagesize`
    """
    pages = []
    for segment in elf.segments:
        if segment.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        va = segment.virtual_address
        assert va % pagesize == segment.file_offset % pagesize, (
            f"PT_LOAD {va:#x} is not congruent with its file offset "
            f"{segment.file_offset:#x} modulo {pagesize:#x}"
        )
        first_page = va // pagesize
        last_page = (va + segment.virtual_size + pagesize - 1) // pagesize
        pages.append((first_page, last_page, va))

    for idx, (first, last, va) in enumerate(pages):
        for other_first, other_last, other_va in pages[idx + 1 :]:
            assert max(first, other_first) >= min(last, other_last), (
                f"PT_LOAD {va:#x} and PT_LOAD {other_va:#x} share the same "
                f"{pagesize:#x} page"
            )


def _add_read_load(binary: lief.ELF.Binary, value: int):
    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.add(lief.ELF.Segment.FLAGS.R)
    segment.content = [value] * 0x50
    assert binary.add(segment) is not None


def _available_phdr_slots(binary: lief.ELF.Binary) -> int:
    phdr = binary.get(lief.ELF.Segment.TYPE.PHDR)
    assert phdr is not None
    phdr_size = 56
    return (
        phdr.physical_size - binary.header.numberof_segments * phdr_size
    ) // phdr_size


@pytest.mark.parametrize(
    ("sample", "pagesize"),
    [
        ("ELF/hello_aarch64_attr", 0x10000),
        ("ELF/libip4tc.so.2.0.0", 0x10000),
        ("ELF/ELF64_AArch64_piebinary_ndkr16.bin", 0x10000),
        ("ELF/bitcoin_ppc_be", 0x10000),
        ("ELF/elf_reader.mips.elf", 0x10000),
    ],
)
def test_set_rpath_interpreter(tmp_path: Path, sample: str, pagesize: int):
    """
    Reproduce the sequence reported in #1366:

    lief-patchelf --set-rpath '${ORIGIN}:${ORIGIN}/../dep' <input>
    lief-patchelf --set-interpreter <interpreter> <input>
    """
    output = tmp_path / "patched.elf"

    elf = parse_elf(sample)
    check_layout(elf)
    _assert_page_compatible(elf, pagesize)

    elf.add(lief.ELF.DynamicEntryRunPath(RUNPATH))
    elf.write(output)

    elf = parse_elf(output)
    check_layout(elf)
    _assert_page_compatible(elf, pagesize)

    elf.interpreter = NEW_INTERPRETER
    elf.write(output)

    elf = parse_elf(output)
    check_layout(elf)
    _assert_page_compatible(elf, pagesize)

    runpath = elf.get(lief.ELF.DynamicEntry.TAG.RUNPATH)
    assert isinstance(runpath, lief.ELF.DynamicEntryRunPath)
    assert runpath.runpath == RUNPATH

    assert elf.has_interpreter
    assert elf.interpreter == NEW_INTERPRETER


def test_add_load_on_fresh_layout_page(tmp_path: Path):
    """A small p_align must not override the binary's 64KB layout."""
    elf = parse_elf("ELF/libip4tc.so.2.0.0")

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.alignment = 0x1000
    segment.file_offset = 0x1000
    segment.content = [0xCC] * 0x40

    assert elf.add(segment) is not None

    output = tmp_path / "added-load.elf"
    elf.write(output)

    built = parse_elf(output)
    check_layout(built)
    _assert_page_compatible(built, 0x10000)


def test_file_end_phdr_relocation(tmp_path: Path):
    """The v3 PHDR LOAD must be congruent for the runtime page size."""
    elf = parse_elf("ELF/libip4tc.so.2.0.0")
    assert elf.relocate_phdr_table(lief.ELF.Binary.PHDR_RELOC.FILE_END) > 0

    output = tmp_path / "file-end.elf"
    elf.write(output)

    built = parse_elf(output)
    check_layout(built)
    _assert_page_compatible(built, 0x10000)

    phdr_load = built.segment_from_offset(built.header.program_header_offset)
    assert phdr_load is not None
    assert phdr_load.type == lief.ELF.Segment.TYPE.LOAD
    assert phdr_load.alignment == 0x10000


@pytest.mark.parametrize(
    "sample",
    [
        ("ELF/hello_aarch64_attr"),
        ("ELF/bitcoin_ppc_be"),
    ],
)
def test_pie_shift(tmp_path: Path, sample: str):
    elf = parse_elf(sample)
    loads = [s for s in elf.segments if s.type == lief.ELF.Segment.TYPE.LOAD]
    moved_load = loads[1]
    original_offset = moved_load.file_offset

    assert elf.relocate_phdr_table(lief.ELF.Binary.PHDR_RELOC.PIE_SHIFT) > 0
    assert moved_load.file_offset - original_offset == 0x10000

    output = tmp_path / Path(sample).name
    elf.write(output)
    built = parse_elf(output)
    check_layout(built)
    _assert_page_compatible(built, 0x10000)


def test_reuse_last_phdr_slots(tmp_path: Path):
    """A builder batch can reuse a reservation with three slots left."""
    output = tmp_path / "reused-phdr.elf"
    elf = parse_elf("ELF/nopie_bss_671.elf")

    for value in range(7):
        _add_read_load(elf, value)

    elf.write(output)
    elf = parse_elf(output)
    check_layout(elf)
    assert elf.header.program_header_offset == 0x3000
    assert _available_phdr_slots(elf) == 3

    elf.add(lief.ELF.DynamicEntryRunPath(RUNPATH))
    elf.write(output)
    elf = parse_elf(output)
    check_layout(elf)
    assert elf.header.program_header_offset == 0x3000
    assert _available_phdr_slots(elf) == 1

    _add_read_load(elf, 7)
    elf.write(output)
    elf = parse_elf(output)
    check_layout(elf)
    assert elf.header.program_header_offset == 0x3000
    assert _available_phdr_slots(elf) == 0


def test_builder_reused_phdr_capacity(tmp_path: Path):
    """A multi-segment rebuild must not partially consume a reservation."""
    output = tmp_path / "one-phdr-slot.elf"
    elf = parse_elf("ELF/nopie_bss_671.elf")

    for value in range(9):
        _add_read_load(elf, value)

    elf.write(output)
    elf = parse_elf(output)
    check_layout(elf)
    assert _available_phdr_slots(elf) == 1

    elf.add(lief.ELF.DynamicEntryRunPath(RUNPATH))
    original_phoff = elf.header.program_header_offset
    original_segment_count = len(elf.segments)

    builder = lief.ELF.Builder(elf)
    builder.build()

    assert len(builder.get_build()) == 0
    assert elf.header.program_header_offset == original_phoff
    assert len(elf.segments) == original_segment_count
    assert _available_phdr_slots(elf) == 1
