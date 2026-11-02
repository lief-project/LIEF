import struct
from pathlib import Path

import lief


def build_elf(*, nbuckets: int = 0, nsyms: int = 2) -> bytes:
    """Build a minimal ELF64 whose DT_GNU_HASH declares ``nbuckets`` buckets."""
    ehsize, phentsize, nph, symsz = 64, 56, 2, 24
    off_dynsym = ehsize + phentsize * nph
    names = [f"sym{i}".encode() for i in range(nsyms)]
    dynstr = b"\0" + b"\0".join(names) + b"\0"

    name_off = {}
    cursor = 1
    for index, name in enumerate(names):
        name_off[index] = cursor
        cursor += len(name) + 1

    dynsym = b"\0" * symsz
    for index in range(nsyms):
        dynsym += struct.pack(
            "<IBBHQQ", name_off[index], 0x12, 0, 1, 0x1000 * (index + 1), 0
        )

    off_dynstr = off_dynsym + len(dynsym)
    off_gnuhash = off_dynstr + len(dynstr)
    gnuhash = struct.pack("<IIII", nbuckets, 1, 1, 5) + struct.pack("<Q", 0)
    gnuhash += struct.pack("<I", 0) * nbuckets

    off_hash = off_gnuhash + len(gnuhash)
    nchain = nsyms + 1
    hashtab = struct.pack("<II", 1, nchain) + struct.pack("<I", 0) * (1 + nchain)

    off_dyn = off_hash + len(hashtab)
    dynamic = b"".join(
        struct.pack("<qQ", tag, value)
        for tag, value in (
            (0x6FFFFEF5, off_gnuhash),  # DT_GNU_HASH
            (4, off_hash),              # DT_HASH
            (6, off_dynsym),            # DT_SYMTAB
            (5, off_dynstr),            # DT_STRTAB
            (10, len(dynstr)),          # DT_STRSZ
            (11, symsz),                # DT_SYMENT
            (0, 0),                     # DT_NULL
        )
    )
    total = off_dyn + len(dynamic)

    phdr = struct.pack("<IIQQQQQQ", 1, 6, 0, 0, 0, total, total, 1)
    phdr += struct.pack(
        "<IIQQQQQQ", 2, 6, off_dyn, off_dyn, 0, len(dynamic), len(dynamic), 1
    )

    ehdr = (
        b"\x7fELF\x02\x01\x01"
        + b"\0" * 9
        + struct.pack(
            "<HHIQQQIHHHHHH",
            3,
            0x3E,
            1,
            0,
            ehsize,
            0,
            0,
            ehsize,
            phentsize,
            nph,
            0,
            0,
            0,
        )
    )
    return ehdr + phdr + dynsym + dynstr + gnuhash + hashtab + dynamic


def test_write_zero_bucket_gnu_hash(tmp_path: Path):
    sample = tmp_path / "zero-buckets.elf"
    sample.write_bytes(build_elf())

    binary = lief.ELF.parse(str(sample))
    assert binary is not None

    output = tmp_path / "rewritten.elf"
    binary.write(str(output))

    assert output.is_file()
    assert lief.ELF.parse(str(output)) is not None
