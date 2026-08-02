import subprocess
import sys
from pathlib import Path
from subprocess import Popen
from textwrap import dedent
from typing import cast

import lief
import pytest
from utils import (
    address_space_limiter,
    check_layout,
    get_sample,
    is_linux,
    is_x86_64,
    parse_elf,
)


def test_issue_863(tmp_path: Path):
    elf = parse_elf("ELF/issue_863.elf")

    assert elf.sysv_hash is not None
    assert elf.sysv_hash.nchain == 7

    elf.remove_dynamic_symbol("puts")

    out = tmp_path / "issue_863.modified"
    elf.write(out)

    check_layout(elf)

    new = lief.ELF.parse(out)
    assert new is not None
    assert new.sysv_hash is not None
    assert new.sysv_hash.nchain == 6


def test_pr_968():
    elf = parse_elf("ELF/echo.mips_r3000.bin")
    sym = cast(lief.ELF.Symbol, elf.get_symbol("strstr"))
    assert sym is not None
    assert sym.imported


def test_issue_1023():
    """
    Make sure that get_content_from_virtual_address return an empty
    buffer when trying to read bss segment
    """
    elf = parse_elf("ELF/nopie_bss_671.elf")

    bss_segment = elf.segments[3]
    bss_start = bss_segment.virtual_address + bss_segment.physical_size
    bss_content = elf.get_content_from_virtual_address(bss_start + 1, 1)

    assert len(bss_content) == 0


def test_issue_1082():
    """
    Make sure RISC-V imported symbols are correctly exported
    """
    elf = parse_elf("ELF/issue-1082-pie.elf")
    imp_symbols = [s.name for s in elf.imported_symbols]
    assert len(imp_symbols) == 6
    assert imp_symbols[0] == "__libc_start_main"
    assert imp_symbols[1] == "printf"
    assert imp_symbols[2] == "__cxa_finalize"
    assert imp_symbols[3] == "__libc_start_main@GLIBC_2.34"
    assert imp_symbols[4] == "printf@GLIBC_2.27"
    assert imp_symbols[5] == "__cxa_finalize@GLIBC_2.27"

    elf = parse_elf("ELF/issue-1082-no_pie.elf")
    imp_symbols = [s.name for s in elf.imported_symbols]
    assert len(imp_symbols) == 4
    assert imp_symbols[0] == "printf"
    assert imp_symbols[2] == "__libc_start_main@GLIBC_2.34"
    assert imp_symbols[3] == "printf@GLIBC_2.27"


def test_issue_1089(tmp_path: Path):
    elf = parse_elf("ELF/libip4tc.so.2.0.0")

    original_nb_relocations = len(elf.dynamic_relocations)

    elf.remove_dynamic_symbol("iptc_read_counter")

    out = tmp_path / "libip4tc.so.2.0.0"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None
    check_layout(new)

    assert new.get_symbol("iptc_read_counter") is None
    assert len(new.dynamic_relocations) == original_nb_relocations - 2


@pytest.mark.private
def test_issue_1097(tmp_path: Path):
    elf = parse_elf("private/ELF/libhwui.so")
    deps = [
        entry.name
        for entry in elf.dynamic_entries
        if isinstance(entry, lief.ELF.DynamicEntryLibrary)
    ]

    out = tmp_path / "libhwui.so"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None
    check_layout(new)
    new_deps = [
        entry.name
        for entry in new.dynamic_entries
        if isinstance(entry, lief.ELF.DynamicEntryLibrary)
    ]

    assert new_deps == deps


def test_issue_1277():
    elf = parse_elf("ELF/issue_1277.elf")
    assert elf is not None


def test_issue_1309(tmp_path: Path):
    elf = parse_elf("ELF/issue_1309.so")
    soname_entry = elf[lief.ELF.DynamicEntry.TAG.SONAME]
    assert soname_entry is not None
    soname_entry.name = "lib" + "a" * 100 + ".so"  # type: ignore

    out = tmp_path / "new.so"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None
    check_layout(new)
    assert list(new.dynamic_symbols)[129].name == "base64_decode_utf16le"


@pytest.mark.private
@pytest.mark.slow
def test_issue_1315(tmp_path: Path):
    # NOTE(romain): there is an exhaustive test here: 'private/ELF/issue_1315'
    #               that includes on-device testing.
    elf = parse_elf("private/ELF/rocksdb-native@3.bare")
    assert elf is not None
    out = tmp_path / "lib.so"

    config = lief.ELF.Builder.config_t()
    config.force_relocate = True

    elf.write(out, config)
    new = lief.ELF.parse(out)
    check_layout(new)


def test_issue_743(tmp_path: Path):
    elf = parse_elf("ELF/ld-linux-x86-64.so.2")

    out = tmp_path / "ld-linux-x86-64.so.2"
    config = lief.ELF.Builder.config_t()
    config.force_relocate = True

    elf.write(out, config)
    new = lief.ELF.parse(out)
    check_layout(new)

    if is_linux() and is_x86_64():
        out.chmod(0o755)
        with Popen(
            [out.as_posix(), "--version"],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            proc.poll()
            assert "Debian GLIBC 2.36-9+deb12u8" in stdout


def test_issue_1342(tmp_path: Path):
    elf = parse_elf("ELF/issue_1309.so")
    assert (
        len(
            [
                r
                for r in elf.dynamic_relocations
                if r.encoding == lief.ELF.Relocation.ENCODING.RELR
            ]
        )
        == 3
    )

    dt_relrsz = elf[lief.ELF.DynamicEntry.TAG.ANDROID_RELRSZ]
    assert dt_relrsz is not None
    assert dt_relrsz.value == 0x10

    new_reloc = lief.ELF.Relocation(
        0xFEA0,
        lief.ELF.Relocation.TYPE.X86_64_RELATIVE,
        lief.ELF.Relocation.ENCODING.RELR,
    )
    elf.add_dynamic_relocation(new_reloc)

    out = tmp_path / "issue_1342.so"
    elf.write(out)

    new = parse_elf(out)
    check_layout(new)

    relr_relocations = [
        r
        for r in new.dynamic_relocations
        if r.encoding == lief.ELF.Relocation.ENCODING.RELR
    ]

    assert len(relr_relocations) == 4

    dt_relrsz = new[lief.ELF.DynamicEntry.TAG.ANDROID_RELRSZ]
    assert dt_relrsz is not None
    assert dt_relrsz.value == 0x18
    assert any(r.address == 0x10EA0 for r in relr_relocations)


def test_runpath_insert_out_of_range():
    sample = Path(get_sample("ELF/elf-HPUX-ia64-bash")).absolute()

    code = dedent("""\
    import lief
    import sys
    lief.logging.disable()
    elf = lief.ELF.parse(sys.argv[1])
    entry = next(e for e in elf.dynamic_entries
                if isinstance(e, lief.ELF.DynamicEntryRunPath))
    original = list(entry.paths)

    entry.insert(len(original) + 1, "/tmp/lief")
    entry.insert(0x10000, "/tmp/lief")
    assert list(entry.paths) == original

    # in-range insertion still works
    entry.insert(1, "/tmp/lief")
    assert list(entry.paths) == original[:1] + ["/tmp/lief"] + original[1:]
    print("OK")""")

    stdout = subprocess.check_output(
        [sys.executable, "-c", code, str(sample)],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )
    assert b"OK" in stdout


def test_section_search_out_of_range():
    """Section.search() with a starting position beyond the section content
    must return None instead of reading out of bounds."""
    sample = Path(get_sample("ELF/ELF64_x86-64_binary_ls.bin")).absolute()

    code = dedent("""\
    import lief
    import sys

    lief.logging.disable()
    elf = lief.ELF.parse(sys.argv[1])
    section = elf.get_section(".text")
    assert section.search(b"\\xff\\xff\\xff\\xff", len(section.content)) is None
    assert section.search(b"\\xff\\xff\\xff\\xff", 0x40000000) is None
    print("OK")""")

    stdout = subprocess.check_output(
        [sys.executable, "-c", code, str(sample)],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )
    assert b"OK" in stdout
