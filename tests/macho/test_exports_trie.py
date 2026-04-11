import subprocess
from pathlib import Path
from typing import cast

import lief
import pytest
from utils import chmod_exe, is_apple_m1, parse_macho, sign


def process(target: lief.MachO.Binary):
    assert target.has(lief.MachO.LoadCommand.TYPE.DYLD_EXPORTS_TRIE)

    exports = cast(
        lief.MachO.DyldExportsTrie,
        target.get(lief.MachO.LoadCommand.TYPE.DYLD_EXPORTS_TRIE),
    )
    assert exports.data_offset == 0x70278

    entries = list(exports.exports)
    entries = sorted(entries, key=lambda e: e.symbol.name)

    assert len(entries) == 885

    assert entries[1].symbol is not None
    assert entries[1].symbol.name == "_main"
    assert entries[1].address == 0x4550

    assert entries[843].symbol is not None
    assert entries[843].symbol.name == "_psa_its_remove"
    assert entries[843].address == 0x3DACC


def test_basic():
    fat = parse_macho(
        "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None

    process(target)
    cmd = target.get(lief.MachO.LoadCommand.TYPE.DYLD_EXPORTS_TRIE)
    assert isinstance(cmd, lief.MachO.DyldExportsTrie)
    assert cmd.data_size == 0x4158


def test_write(tmp_path: Path):
    binary_name = "crypt_and_hash"
    fat = parse_macho(
        "MachO/9edfb04c55289c6c682a25211a4b30b927a86fe50b014610d04d6055bd4ac23d_crypt_and_hash.macho"
    )
    target = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert target is not None

    output = f"{tmp_path}/{binary_name}.built"

    target.write(output)
    fat_parsed = lief.MachO.parse(output)
    assert fat_parsed is not None
    target = fat_parsed.at(0)
    assert target is not None

    process(target)

    valid, err = lief.MachO.check_layout(target)
    assert valid, err

    if is_apple_m1():
        chmod_exe(output)
        sign(output)
        with subprocess.Popen(
            [output],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            assert "CAMELLIA-256-CCM*-NO-TAG" in stdout
            assert "AES-128-CCM*-NO-TAG" in stdout


@pytest.mark.private
@pytest.mark.slow
def test_issue_1262():
    macho = parse_macho("private/MachO/issue-1262.macho").at(0)
    assert macho is not None

    dyld_trie = macho.dyld_exports_trie
    assert dyld_trie is not None
    assert len(dyld_trie.exports) == 312478
