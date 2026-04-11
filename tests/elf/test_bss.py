import os
import stat
import subprocess
from pathlib import Path
from subprocess import Popen

import lief
import pytest
from utils import check_layout, is_64bits_platform, is_linux, is_x86_64, parse_elf


def test_issue_671(tmp_path: Path):
    """
    Test the support of bss-like segments where `virtual_address - imagebase != offset`
    see: https://github.com/lief-project/LIEF/issues/671
    """
    binary_name = "nopie_bss_671.elf"
    target = parse_elf(f"ELF/{binary_name}")

    for s in filter(lambda e: e.exported, target.symtab_symbols):
        target.add_dynamic_symbol(s)

    output = tmp_path / binary_name
    target.write(output)

    # Make sure that the PHDR has been relocated at the end:
    built = lief.ELF.parse(output)
    assert built is not None
    check_layout(built)
    phdr_seg = built.get(lief.ELF.Segment.TYPE.PHDR)
    assert phdr_seg is not None
    assert phdr_seg.file_offset == 0x3000
    assert phdr_seg.physical_size == 0x1F8
    assert phdr_seg.virtual_address == 0x403000

    if is_linux() and is_x86_64():
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(
            output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as P:
            assert P.stdout is not None
            stdout = P.stdout.read().decode("utf8")
            lief.logging.info(stdout)
            assert len(stdout) > 0


@pytest.mark.slow
def test_all(tmp_path: Path):
    if not is_64bits_platform():
        pytest.skip("requires a 64-bits platform")

    binary_name = "544ca2035a9c15e7756ed8d8067d860bd3157e4eeaa39b4ee932458eebe2434b.elf"
    target = parse_elf(f"ELF/{binary_name}")
    bss = target.get_section(".bss")
    assert bss is not None

    assert bss.virtual_address == 0x65A3E0
    assert bss.size == 0x1CCB6330
    assert bss.file_offset == 0x05A3E0
    assert len(bss.content) == 0

    target.add_library("libcap.so.2")
    # Add segment
    new_segment = lief.ELF.Segment()
    new_segment.type = lief.ELF.Segment.TYPE.LOAD
    new_segment.content = [0xCC] * 0x50
    target.add(new_segment)

    output = tmp_path / f"{binary_name}.build"
    target.write(output)

    check_layout(output)

    if is_linux() and is_x86_64():
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(output, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
            assert P.stdout is not None
            stdout = P.stdout.read().decode("utf8")
            lief.logging.info(stdout)
            assert len(stdout) > 0

    # Check that the written binary contains our modifications
    new = parse_elf(output)
    lib = new.get_library("libcap.so.2")
    assert lib is not None
    assert lib.name == "libcap.so.2"
