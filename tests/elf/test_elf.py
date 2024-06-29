#!/usr/bin/env python
import itertools
import os
import random
import stat
import subprocess
import pytest
from pathlib import Path
from subprocess import Popen

import lief
from utils import get_sample, has_recent_glibc, is_linux, is_x86_64

is_updated_linux = is_linux() and is_x86_64() and has_recent_glibc()

lief.logging.set_level(lief.logging.LEVEL.INFO)


def test_rpath():
    etterlog = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))

    dynamic_entries = etterlog.dynamic_entries

    rpath = [e for e in dynamic_entries if e.tag == lief.ELF.DynamicEntry.TAG.RPATH]

    assert len(rpath) == 1
    last = rpath.pop()
    assert isinstance(last, lief.ELF.DynamicEntryRpath)
    assert last.rpath == "/usr/lib"

def test_runpath():
    etterlog = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_systemd-resolve.bin'))

    dynamic_entries = etterlog.dynamic_entries

    runpath = [e for e in dynamic_entries if e.tag == lief.ELF.DynamicEntry.TAG.RUNPATH]

    assert len(runpath) == 1
    last = runpath.pop()
    assert isinstance(last, lief.ELF.DynamicEntryRunPath)
    assert last.runpath == "/usr/lib/systemd"


def test_gnuhash():
    ls = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_ls.bin'))
    gnu_hash = ls.gnu_hash

    assert gnu_hash.nb_buckets == 33
    assert gnu_hash.symbol_index == 109
    assert gnu_hash.shift2 == 7

    bloom_filters = gnu_hash.bloom_filters

    assert len(bloom_filters) == 2
    assert 0x3FAE01120C48A1A6 in bloom_filters
    assert 0x900004A81310D428 in bloom_filters

    buckets = gnu_hash.buckets
    assert len(buckets) == 33

    buckets_test = [109, 110, 0, 0, 0, 0, 0, 111, 113, 114, 0, 0, 0, 115, 0, 116, 0, 0,
                    117, 118, 119, 0, 120, 0, 0, 121, 123, 124, 126, 128, 129, 130, 0]
    assert buckets_test == buckets


    hash_values = gnu_hash.hash_values
    hash_values_test = [0x60E0C78D, 0xF54162E5, 0x7FFD8E4E, 0x1C8BF239, 0x0EEFD3EB, 0x1C8C1D29, 0x1C5871D9,
                        0x5B7F3E03, 0x759A6A7F, 0x0EF18DB9, 0x0BA53E4D, 0x9789A097, 0x9E7650BC, 0x0D39AD3D,
                        0x12F7C433, 0xEB01FAB6, 0xECD54543, 0xAD3C9892, 0x72632CCF, 0x12F7A2B3, 0x7C92E3BB,
                        0x7C96F087]
    assert hash_values == hash_values_test

    #for s in list(ls.dynamic_symbols)[gnu_hash.symbol_index:]:
    #    print(gnu_hash.check(s.name), s.name)
    assert all(gnu_hash.check(x.name) for x in list(ls.dynamic_symbols)[gnu_hash.symbol_index:]) # type: ignore

    assert not gnu_hash.check("foofdsfdsfds")
    assert not gnu_hash.check("fazertrvkdfsrezklqpfjeopqdi")

@pytest.mark.parametrize("sample", [
    "ELF/ELF64_x86-64_binary_ls.bin"
])
def test_permutation(tmp_path: Path, sample: str):

    binary = lief.ELF.parse(get_sample(sample))
    dynamic_symbols = binary.dynamic_symbols

    permutation = list(range(1, len(dynamic_symbols)))
    random.shuffle(permutation)
    permutation = [0] + permutation
    binary.permute_dynamic_symbols(permutation)

    builder = lief.ELF.Builder(binary)
    builder.build()
    output = tmp_path / "out.permutated"
    print(f"Output: {output}")
    builder.write(output.as_posix())

    if not is_updated_linux:
        return

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen([output, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode('utf8')
        print(stdout)
        P.communicate()
        assert P.returncode == 0

def test_notes():
    systemd_resolve = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_systemd-resolve.bin'))
    notes = systemd_resolve.notes
    assert len(notes) == 3

    n1 = notes[0]
    n2 = notes[1]
    n3 = notes[2]

    assert n1.name == "GNU"
    assert n2.name == "GNU"
    assert n3.name == "GNU"

    assert n1.type == lief.ELF.Note.TYPE.GNU_ABI_TAG
    assert n2.type == lief.ELF.Note.TYPE.GNU_BUILD_ID
    assert n3.type == lief.ELF.Note.TYPE.GNU_GOLD_VERSION

    assert isinstance(n1, lief.ELF.NoteAbi)

    assert n1.abi == lief.ELF.NoteAbi.ABI.LINUX
    assert n1.version == [2, 6, 32]

    assert list(n2.description) == [0x7e, 0x68, 0x6c, 0x7d,
                                    0x79, 0x9b, 0xa4, 0xcd,
                                    0x32, 0xa2, 0x34, 0xe8,
                                    0x4f, 0xd7, 0x45, 0x98,
                                    0x21, 0x32, 0x9d, 0xc8]

    assert "".join(map(chr, n3.description)) == "gold 1.12\x00\x00\x00"

def test_symbols_access():
    hello = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_hello-gdb.bin'))

    symbols         = hello.symbols
    dynamic_symbols = hello.dynamic_symbols
    symtab_symbols  = hello.symtab_symbols

    assert all(s in symbols for s in dynamic_symbols)
    assert all(s in symbols for s in symtab_symbols)

def test_strings():
    hello = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_all.bin'))

    assert len(hello.strings) > 0
    assert "add_1" in hello.strings

def test_relocation_size():
    aarch64_toybox = lief.ELF.parse(get_sample('ELF/ELF64_AARCH64_piebinary_toybox.pie'))
    arm_ls         = lief.ELF.parse(get_sample('ELF/ELF32_ARM_binary_ls.bin'))
    x86_ls         = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_ls.bin'))
    x86_64_ls      = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_ld.bin'))

    for r in itertools.chain(aarch64_toybox.dynamic_relocations, aarch64_toybox.pltgot_relocations):
        if r.type == lief.ELF.Relocation.TYPE.AARCH64_RELATIVE:
            assert r.size == 64

        if r.type == lief.ELF.Relocation.TYPE.AARCH64_GLOB_DAT:
            assert r.size == 64

        if r.type == lief.ELF.Relocation.TYPE.AARCH64_JUMP_SLOT:
            assert r.size == 64

    for r in itertools.chain(arm_ls.dynamic_relocations, arm_ls.pltgot_relocations):
        if r.type == lief.ELF.Relocation.TYPE.ARM_RELATIVE:
            assert r.size == 32

        if r.type == lief.ELF.Relocation.TYPE.ARM_GLOB_DAT:
            assert r.size == 32

        if r.type == lief.ELF.Relocation.TYPE.ARM_ABS32:
            assert r.size == 32

        if r.type == lief.ELF.Relocation.TYPE.ARM_JUMP_SLOT:
            assert r.size == 32


    for r in itertools.chain(x86_ls.dynamic_relocations, x86_ls.pltgot_relocations):
        if r.type == lief.ELF.Relocation.TYPE.X86_GLOB_DAT:
            assert r.size == 32

        if r.type == lief.ELF.Relocation.TYPE.X86_COPY:
            assert r.size == 32

        if r.type == lief.ELF.Relocation.TYPE.X86_JUMP_SLOT:
            assert r.size == 32


    for r in itertools.chain(x86_64_ls.dynamic_relocations, x86_64_ls.pltgot_relocations):
        if r.type == lief.ELF.Relocation.TYPE.X86_64_GLOB_DAT:
            assert r.size == 64

        if r.type == lief.ELF.Relocation.TYPE.X86_64_COPY:
            assert r.size == 32

        if r.type == lief.ELF.Relocation.TYPE.X86_64_JUMP_SLOT:
            assert r.size == 64

def test_sectionless():
    sample = "ELF/ELF64_x86-64_binary_rvs.bin"
    rvs = lief.ELF.parse(get_sample(sample))
    dynsym = list(rvs.dynamic_symbols)
    assert len(dynsym) == 10

def test_dynamic_flags():
    sample = "ELF/ELF32_ARM_binary_ls.bin"
    ls = lief.ELF.parse(get_sample(sample))
    d_flags = ls.get(lief.ELF.DynamicEntry.TAG.FLAGS)
    d_flags_1 = ls.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)

    assert isinstance(d_flags, lief.ELF.DynamicEntryFlags)
    assert isinstance(d_flags_1, lief.ELF.DynamicEntryFlags)

    assert lief.ELF.DynamicEntryFlags.FLAG.BIND_NOW in d_flags
    assert lief.ELF.DynamicEntryFlags.FLAG.NOW in d_flags_1


def test_unwind_arm():
    sample = "ELF/ELF32_ARM_binary_ls.bin"
    ls = lief.ELF.parse(get_sample(sample))

    assert ls.original_size == Path(get_sample(sample)).stat().st_size

    functions = sorted(ls.functions, key=lambda f: f.address)

    assert len(functions) == 265

    assert functions[0].address == 19684
    assert functions[0].size == 0
    assert functions[0].name == "open"

    assert functions[-1].address == 102372
    assert functions[-1].size == 0
    assert functions[-1].name == ""


def test_unwind_x86():
    sample = "ELF/ELF64_x86-64_binary_ld.bin"
    ld = lief.ELF.parse(get_sample(sample))

    functions = sorted(ld.functions, key=lambda f: f.address)

    assert len(functions) == 503

    assert functions[0].address == 4209304
    assert functions[0].size == 0
    assert functions[0].name == "_init"

    assert functions[10].size == 174
    assert functions[10].name == ""

    assert functions[-1].address == 4409396
    assert functions[-1].size == 0
    assert functions[-1].name == "_fini"


def test_misc():
    sample = "ELF/ELF64_x86-64_binary_ld.bin"
    ld = lief.ELF.parse(get_sample(sample))

    text = ld.get_section(".text")

    assert not ld.has_section_with_offset(0)
    assert not ld.has_section_with_va(0xFFFFFFFF)

    assert ld.has_section_with_offset(text.offset + 10)
    assert ld.has_section_with_va(text.virtual_address + 10)

    assert lief.ELF.Segment.from_raw(b"") == lief.lief_errors.corrupted

    raw = """
    06 00 00 00 04 00 00 00 40 00 00 00 00 00 00 00
    40 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
    d8 02 00 00 00 00 00 00 d8 02 00 00 00 00 00 00
    08 00 00 00 00 00 00 00
    """
    raw = raw.replace("\n", "") \
             .replace("  ", " ") \
             .replace("  ", " ").strip()
    hexdigits = raw.split(" ")
    raw_bytes = bytes(int(c, 16) for c in hexdigits)

    assert isinstance(lief.ELF.Segment.from_raw(raw_bytes), lief.ELF.Segment)
