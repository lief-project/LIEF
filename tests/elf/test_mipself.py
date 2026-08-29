from pathlib import Path

import lief
from utils import check_layout, parse_elf


def test_mipsel():
    elf = parse_elf("ELF/libdep_mipsel.so")
    assert not elf.header.is_mips_n64
    assert elf.header.flags_list == [
        lief.ELF.PROCESSOR_FLAGS.MIPS_NOREORDER,
        lief.ELF.PROCESSOR_FLAGS.MIPS_PIC,
        lief.ELF.PROCESSOR_FLAGS.MIPS_CPIC,
        lief.ELF.PROCESSOR_FLAGS.MIPS_ABI_O32,
        lief.ELF.PROCESSOR_FLAGS.MIPS_ARCH_32R2,
    ]

    mips_abiflags = elf.get_section(".MIPS.abiflags")
    assert mips_abiflags is not None
    assert mips_abiflags.type == lief.ELF.Section.TYPE.MIPS_ABIFLAGS
    reginfo = elf.get_section(".reginfo")
    assert reginfo is not None
    assert reginfo.type == lief.ELF.Section.TYPE.MIPS_REGINFO

    assert elf.segments[1].type == lief.ELF.Segment.TYPE.MIPS_REGINFO

    rld_version = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_RLD_VERSION)
    assert rld_version is not None
    assert rld_version.value == 1
    mips_flags = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_FLAGS)
    assert mips_flags is not None
    assert mips_flags.value == 2
    mips_base = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_BASE_ADDRESS)
    assert mips_base is not None
    assert mips_base.value == 0
    mips_local_gotno = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_LOCAL_GOTNO)
    assert mips_local_gotno is not None
    assert mips_local_gotno.value == 9
    mips_symtabno = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_SYMTABNO)
    assert mips_symtabno is not None
    assert mips_symtabno.value == 21
    mips_unrefextno = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_UNREFEXTNO)
    assert mips_unrefextno is not None
    assert mips_unrefextno.value == 35
    mips_gotsym = elf.get(lief.ELF.DynamicEntry.TAG.MIPS_GOTSYM)
    assert mips_gotsym is not None
    assert mips_gotsym.value == 3

    if lief.__extended__:
        inst = list(elf.disassemble("onload"))
        assert len(inst) == 191
        assert inst[0] is not None
        assert inst[0].to_string() == "0x000fa4: lui $gp, 0x2"
        assert inst[190] is not None
        assert inst[190].to_string() == "0x00129c: nop"


def test_add_library_mips_be(tmp_path: Path):
    """
    Adding a DT_NEEDED entry through add_library (see issue/)
    """
    elf = parse_elf("ELF/elf_reader.mips.elf")

    assert elf.header.identity_class == lief.ELF.Header.CLASS.ELF32
    assert elf.header.identity_data == lief.ELF.Header.ELF_DATA.MSB
    assert elf.header.machine_type == lief.ELF.ARCH.MIPS
    assert not elf.header.is_mips_n64

    entry = elf.add_library("libfoo_be.so")
    assert entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED
    assert entry.name == "libfoo_be.so"

    output = tmp_path / "elf_reader.mips.add_library.elf"
    elf.write(output)

    check_layout(output)

    new = parse_elf(output)
    assert new.get_library("libfoo_be.so") is not None


def test_mips_n64_le_relocations(tmp_path: Path):
    """
    MIPS n64 little-endian binaries store relocations in the
    MIPS-specific `Elf64_Mips_External_Rel` layout

    See: PR #1367
    """

    elf = parse_elf("ELF/libtest_mips64el_n64.bin")

    assert elf.header.identity_class == lief.ELF.Header.CLASS.ELF64
    assert elf.header.identity_data == lief.ELF.Header.ELF_DATA.LSB
    assert elf.header.machine_type == lief.ELF.ARCH.MIPS
    assert elf.header.is_mips_n64

    packed = lief.ELF.Relocation(
        0,
        lief.ELF.Relocation.TYPE.MIPS_REL32,
        lief.ELF.Relocation.ENCODING.ANDROID_SLEB,
    )
    packed.info = 0x123
    assert packed.r_info(elf.header) == (0x123 << 32) | 3

    dynsym = elf.dynamic_symbols
    assert len(dynsym) == 10

    relocs = list(elf.relocations)
    assert len(relocs) == 4

    types = {r.type for r in relocs}
    assert lief.ELF.Relocation.TYPE.MIPS_REL32 in types

    for r in relocs:
        assert r.info < len(dynsym)

    relative = next(r for r in relocs if r.type == lief.ELF.Relocation.TYPE.MIPS_REL32)
    base_address = 0x1000_0000_0000
    assert relative.resolve(base_address) == base_address + 0x7B8

    raw_info = relative.r_info(elf.header)
    original_purpose = relative.purpose
    relative.purpose = lief.ELF.Relocation.PURPOSE.OBJECT
    assert relative.purpose == lief.ELF.Relocation.PURPOSE.OBJECT
    assert relative.r_info(elf.header) == raw_info
    relative.purpose = original_purpose

    wide_addend = 0x1_0000_07B8
    elf.patch_address(relative.address, wide_addend, 8)
    assert relative.resolve(base_address) == base_address + wide_addend
    elf.patch_address(relative.address, 0x7B8, 8)

    raw_infos = [r.r_info(elf.header) for r in relocs]

    out = tmp_path / "mips64el_n64_rt.so"
    elf.write(out)
    reparsed = parse_elf(out)
    check_layout(reparsed)

    for orig, rt, raw_info in zip(relocs, reparsed.relocations, raw_infos):
        assert orig.type == rt.type
        assert orig.info == rt.info
        assert rt.r_info(reparsed.header) == raw_info


def test_mips_n64_be_relocations(tmp_path: Path):
    """See: PR #1367"""
    elf = parse_elf("ELF/libtest_mips64_n64_be.o")

    assert elf.header.identity_class == lief.ELF.Header.CLASS.ELF64
    assert elf.header.identity_data == lief.ELF.Header.ELF_DATA.MSB
    assert elf.header.machine_type == lief.ELF.ARCH.MIPS
    assert elf.header.is_mips_n64

    relocs = list(elf.relocations)
    types = {r.type for r in relocs}

    assert lief.ELF.Relocation.TYPE.MIPS_GPREL16 in types
    assert lief.ELF.Relocation.TYPE.MIPS_GOT_DISP in types
    assert lief.ELF.Relocation.TYPE.MIPS_32 in types

    got_disp = sorted(
        r.symbol.name
        for r in relocs
        if r.symbol is not None and r.type == lief.ELF.Relocation.TYPE.MIPS_GOT_DISP
    )
    assert got_disp == ["bar", "foo", "g"]

    raw_infos = [r.r_info(elf.header) for r in relocs]
    out = tmp_path / "mips64_n64_be_rt.o"
    elf.write(out)
    reparsed = parse_elf(out)

    assert sorted(r.r_info(reparsed.header) for r in reparsed.relocations) == sorted(
        raw_infos
    )
