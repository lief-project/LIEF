import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import lief
import pytest
from utils import address_space_limiter, get_sample, parse_elf

CWD = Path(__file__).parent


def test_symbols():
    target = parse_elf("ELF/ELF32_x86_library_libshellx.so")
    symbols = [
        sym
        for idx, sym in enumerate(target.dynamic_symbols)
        if idx == 0 or len(sym.name) > 0
    ]
    assert len(symbols) == 48

    assert symbols[2].name == "__cxa_atexit"


def test_relocations():
    target = parse_elf("ELF/ELF32_x86_library_libshellx.so")
    relocations = target.relocations
    assert len(relocations) == 47

    assert relocations[10].symbol is not None
    assert relocations[10].symbol.name == "strlen"


@pytest.mark.linux
@pytest.mark.private
def test_section_overflow():
    sample = Path(get_sample("private/ELF/section_overflow.elf")).absolute()

    subprocess.check_call(
        [sys.executable, "-c", f'import lief; lief.parse(r"{sample}")'],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )


@pytest.mark.private
def test_dynamic_entries_capped():
    sample = get_sample("private/ELF/dynamic_no_null.elf")
    elf = lief.ELF.parse(sample)
    assert elf is not None
    assert len(elf.dynamic_entries) == 1000


@pytest.mark.private
def test_gnu_hash_zero():
    sample = get_sample("private/ELF/corrupted_gnu_hash.elf")
    if lief.__extended__:
        pytest.skip(reason="TODO(romain): broken on the CI (only)")

    script = dedent(f"""\
        import lief;
        b = lief.ELF.parse(r'{sample}');
        assert b is not None;
        gh = b.gnu_hash;
        assert gh is not None;
        assert gh.nb_buckets == 0 and len(gh.bloom_filters) == 0;
        assert gh.check('foo') is False;
        assert gh.check_bucket(0) is False;
        assert gh.check_bloom_filter(0) is False""")
    subprocess.check_call([sys.executable, "-c", script], timeout=10.0)


def test_section_segment_links():
    elf = lief.ELF.parse(CWD / "hello_lief.bin")
    assert elf is not None
    assert sum(len(section.segments) for section in elf.sections) == 11

    dynamic = elf.get_section(".dynamic")
    assert dynamic is not None
    assert [segment.type for segment in dynamic.segments] == [
        lief.ELF.Segment.TYPE.LOAD,
        lief.ELF.Segment.TYPE.DYNAMIC,
        lief.ELF.Segment.TYPE.GNU_RELRO,
    ]

    pt_load = elf.segments[0]
    assert [section.name for section in pt_load.sections] == [
        ".hash",
        ".dynsym",
        ".dynstr",
        ".text",
        ".rodata",
        ".eh_frame_hdr",
        ".eh_frame",
    ]


@pytest.mark.private
@pytest.mark.linux
def test_section_segment_links_capped():
    nb_sections = 0xFFFF
    nb_segments = 10_000

    fixture = Path(get_sample("private/ELF/section_segment_links.elf")).absolute()

    code = dedent(f"""\
    import lief
    import sys
    lief.logging.disable()
    elf = lief.ELF.parse(sys.argv[1])
    assert elf is not None
    assert len(elf.sections) == {nb_sections}
    assert len(elf.segments) == {nb_segments}
    nb_links = sum(len(segment.sections) for segment in elf.segments)
    assert nb_links == 1_000_000, nb_links
    assert nb_links == sum(len(section.segments) for section in elf.sections)
    """)

    subprocess.check_call(
        [sys.executable, "-c", code, str(fixture)],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )
