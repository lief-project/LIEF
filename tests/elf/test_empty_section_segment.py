from pathlib import Path

import lief

from utils import check_layout

CWD = Path(__file__).parent
STUB = CWD / "hello_lief.bin"


def _parse_stub() -> lief.ELF.Binary:
    binary = lief.ELF.parse(STUB)
    assert binary is not None
    return binary


def test_add_empty_section_not_loaded(tmp_path: Path) -> None:
    binary = _parse_stub()
    original_size = STUB.stat().st_size

    section = lief.ELF.Section(".lief.empty")
    section.type = lief.ELF.Section.TYPE.NOBITS
    section.size = 0x1234
    section.alignment = 0x10
    section.add(lief.ELF.Section.FLAGS.ALLOC)
    section.add(lief.ELF.Section.FLAGS.WRITE)

    added = binary.add(section, loaded=False)
    assert added is not None
    assert added.type == lief.ELF.Section.TYPE.NOBITS
    assert added.size == 0x1234
    assert bytes(added.content) == b""

    output = tmp_path / "empty_section_unloaded.elf"
    binary.write(output)
    check_layout(output)

    # The 0x1234 bytes described by the section are not stored in the file.
    assert output.stat().st_size < original_size + 0x1234

    parsed = lief.ELF.parse(output)
    assert parsed is not None
    parsed_section = parsed.get_section(".lief.empty")
    assert parsed_section is not None
    assert parsed_section.type == lief.ELF.Section.TYPE.NOBITS
    assert parsed_section.size == 0x1234
    assert bytes(parsed_section.content) == b""


def test_add_empty_section_loaded(tmp_path: Path) -> None:
    binary = _parse_stub()

    section = lief.ELF.Section(".lief.empty.loaded")
    section.type = lief.ELF.Section.TYPE.NOBITS
    section.size = 0x2000
    section.alignment = 0x10
    section.add(lief.ELF.Section.FLAGS.ALLOC)
    section.add(lief.ELF.Section.FLAGS.WRITE)

    added = binary.add(section, loaded=True)
    assert added is not None
    assert added.size == 0x2000
    assert added.virtual_address != 0
    assert bytes(added.content) == b""

    load_segments = [
        seg for seg in added.segments if seg.type == lief.ELF.Segment.TYPE.LOAD
    ]
    assert load_segments
    assert any(
        seg.physical_size == 0 and seg.virtual_size >= 0x2000
        for seg in load_segments
    )

    output = tmp_path / "empty_section_loaded.elf"
    binary.write(output)
    check_layout(output)

    parsed = lief.ELF.parse(output)
    assert parsed is not None
    parsed_section = parsed.get_section(".lief.empty.loaded")
    assert parsed_section is not None
    assert parsed_section.type == lief.ELF.Section.TYPE.NOBITS
    assert parsed_section.size == 0x2000
    assert bytes(parsed_section.content) == b""

    containing = [
        seg
        for seg in parsed.segments
        if seg.type == lief.ELF.Segment.TYPE.LOAD
        and seg.virtual_address
        <= parsed_section.virtual_address
        < seg.virtual_address + seg.virtual_size
    ]
    assert containing
    assert any(
        seg.physical_size == 0 and seg.virtual_size >= 0x2000 for seg in containing
    )


def test_add_empty_segment(tmp_path: Path) -> None:
    binary = _parse_stub()
    original_size = STUB.stat().st_size

    segment = lief.ELF.Segment()
    segment.type = lief.ELF.Segment.TYPE.LOAD
    segment.add(lief.ELF.Segment.FLAGS.R)
    segment.add(lief.ELF.Segment.FLAGS.W)
    segment.virtual_size = 0x4000
    segment.alignment = 0x1000

    added = binary.add(segment)
    assert added is not None
    assert added.type == lief.ELF.Segment.TYPE.LOAD
    assert added.physical_size == 0
    assert added.virtual_size == 0x4000
    assert bytes(added.content) == b""
    assert added.has(lief.ELF.Segment.FLAGS.R)
    assert added.has(lief.ELF.Segment.FLAGS.W)

    output = tmp_path / "empty_segment.elf"
    binary.write(output)
    check_layout(output)

    # The 0x4000 bytes reserved in memory are not stored in the file.
    assert output.stat().st_size < original_size + 0x4000

    parsed = lief.ELF.parse(output)
    assert parsed is not None
    candidates = [
        seg for seg in parsed.segments if seg.virtual_address == added.virtual_address
    ]
    assert len(candidates) == 1
    parsed_segment = candidates[0]
    assert parsed_segment.type == lief.ELF.Segment.TYPE.LOAD
    assert parsed_segment.physical_size == 0
    assert parsed_segment.virtual_size == 0x4000
    assert bytes(parsed_segment.content) == b""
    assert parsed_segment.has(lief.ELF.Segment.FLAGS.R)
    assert parsed_segment.has(lief.ELF.Segment.FLAGS.W)
