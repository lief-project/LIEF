import struct
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import lief
import pytest
from utils import address_space_limiter, get_sample


def _overlapping_sections_pe(nb_sections: int, file_size: int) -> bytes:
    alignment = 0x1000
    optional_size = 0xE0
    pe_offset = 0x40
    coff_offset = pe_offset + 4
    optional_offset = coff_offset + 20
    sections_offset = optional_offset + optional_size
    span = (file_size + alignment - 1) // alignment * alignment
    headers_end = sections_offset + nb_sections * 40
    assert headers_end <= file_size

    raw = bytearray(b"\xcc" * file_size)
    raw[:headers_end] = b"\x00" * headers_end
    raw[0:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, pe_offset)
    raw[pe_offset : pe_offset + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH", raw, coff_offset, 0x14C, nb_sections, 0, 0, 0, optional_size, 0x0102
    )
    struct.pack_into("<H", raw, optional_offset, 0x10B)
    struct.pack_into("<I", raw, optional_offset + 28, 0x400000)
    struct.pack_into("<II", raw, optional_offset + 32, alignment, 0x200)
    struct.pack_into("<I", raw, optional_offset + 56, alignment + nb_sections * span)
    struct.pack_into("<I", raw, optional_offset + 60, headers_end)
    struct.pack_into("<H", raw, optional_offset + 68, 3)
    struct.pack_into("<I", raw, optional_offset + 92, 16)
    for i in range(nb_sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            raw,
            sections_offset + i * 40,
            f".s{i}".encode(),
            file_size,
            alignment + i * span,
            file_size,
            0,
            0,
            0,
            0,
            0,
            0x40000040,
        )
    return bytes(raw)


def test_overlapping_sections_content():
    file_size = 64 * 1024
    raw = _overlapping_sections_pe(1000, file_size)
    binary = lief.PE.parse(raw)
    assert binary is not None

    sections = list(binary.sections)
    assert len(sections) == 1000
    for section in sections:
        content = bytes(section.content)
        assert len(content) == file_size
        assert content == raw


@pytest.mark.linux
def test_overlapping_sections_memory():
    code = dedent("""\
    import sys
    import lief

    raw = sys.stdin.buffer.read()
    binary = lief.PE.parse(raw)
    assert binary is not None
    assert len(binary.sections) == 1000
    for section in binary.sections:
        assert bytes(section.content) == raw
    print("OK")""")

    raw = _overlapping_sections_pe(1000, 1 << 20)
    stdout = subprocess.check_output(
        [sys.executable, "-c", code],
        input=raw,
        timeout=120.0,
        preexec_fn=address_space_limiter(512 * 1024 * 1024),
    )

    assert b"OK" in stdout


@pytest.mark.parametrize("test_name", ["pr_1371_0.exe", "pr_1371_1.exe"])
def test_aarch64_epilog_scopes_dos(test_name: str):
    sample = Path(get_sample(f"PE/{test_name}")).absolute()

    code = dedent("""\
    import lief
    import sys
    lief.logging.disable()
    config = lief.PE.ParserConfig()
    config.parse_exceptions = True
    pe = lief.PE.parse(sys.argv[1], config)
    assert pe is not None
    scopes = sum(len(e.epilog_scopes) for e in pe.exceptions
                 if isinstance(e, lief.PE.unwind_aarch64.UnpackedFunction))
    assert scopes < 1_000_000, scopes
    print("OK")""")

    stdout = subprocess.check_output(
        [sys.executable, "-c", code, str(sample)],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )

    assert b"OK" in stdout


@pytest.mark.private
def test_patch_address_out_of_segment():
    GAP = 0x20_000_000
    sample = Path(get_sample("private/PE/bss_issue.exe")).absolute()

    code = dedent(f"""\
    import lief
    import sys
    lief.logging.disable()
    pe = lief.PE.parse(sys.argv[1])
    sec = next(s for s in pe.sections if s.virtual_size > len(s.content) > 0)
    rva = sec.virtual_address + len(sec.content) + {GAP // 2}
    pe.patch_address(rva, 0x4141414141414141, 8, lief.Binary.VA_TYPES.RVA)
    print("OK")""")

    stdout = subprocess.check_output(
        [sys.executable, "-c", code, str(sample)],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )

    assert b"OK" in stdout
