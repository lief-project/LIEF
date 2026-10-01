import struct
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest
from utils import address_space_limiter, get_sample


def _aarch64_epilog_bomb(n_entries: int, section_pad: int) -> bytes:
    """ARM64 PE whose n_entries .pdata records all point at one unwind record
    claiming 65535 epilog scopes. section_pad=0 makes the scope array exactly
    fill its section (tripping the per-section bound); slack lets it pass so only
    the aggregate budget caps the total."""
    file_align, sect_align = 0x200, 0x1000
    align = lambda v, b: (v + b - 1) // b * b

    headers = align(0x80 + 4 + 20 + 240 + 2 * 40, file_align)
    # extended header (word1=0), E=0, epilog_count=0xFFFF
    xdata = struct.pack("<II", 0, 0xFFFF) + b"\xAA" * (65535 * 4) + b"\x00" * section_pad
    pdata_size = n_entries * 8
    pdata_rva = sect_align
    xdata_rva = pdata_rva + align(pdata_size, sect_align)
    pdata = b"".join(struct.pack("<II", 0x1000 + i * 4, xdata_rva)
                     for i in range(n_entries))

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x80)
    dos += b"\x00" * (0x80 - len(dos))
    coff = struct.pack("<HHIIIHH", 0xAA64, 2, 0, 0, 0, 240, 0x0022)
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
                      0x20B, 14, 0, 0, 0, 0, 0, 0, 0x140000000, sect_align,
                      file_align, 6, 0, 0, 0, 6, 0, 0,
                      xdata_rva + align(len(xdata), sect_align), headers, 0, 3, 0,
                      0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = [(0, 0)] * 16
    dirs[3] = (pdata_rva, pdata_size)
    opt += b"".join(struct.pack("<II", rva, size) for rva, size in dirs)

    def section(name, rva, vsize, off, raw):
        return name.ljust(8, b"\x00") + struct.pack(
            "<IIIIIIHHI", vsize, rva, raw, off, 0, 0, 0, 0, 0x40000040)

    pdata_off = headers
    xdata_off = pdata_off + align(pdata_size, file_align)
    sections = (section(b".pdata", pdata_rva, pdata_size, pdata_off,
                        align(pdata_size, file_align)) +
                section(b".rdata", xdata_rva, len(xdata), xdata_off,
                        align(len(xdata), file_align)))

    out = bytearray(dos + b"PE\x00\x00" + coff + opt + sections)
    out += b"\x00" * (headers - len(out))
    out += pdata.ljust(align(pdata_size, file_align), b"\x00")
    out += xdata.ljust(align(len(xdata), file_align), b"\x00")
    return bytes(out)


@pytest.mark.parametrize("section_pad", [0, 0x20000],
                         ids=["section_bound", "scope_budget"])
def test_aarch64_epilog_scopes_dos(tmp_path, section_pad):
    sample = tmp_path / "epilog_bomb.exe"
    sample.write_bytes(_aarch64_epilog_bomb(20000, section_pad))

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
