from pathlib import Path

import lief
import pytest
from utils import parse_macho


@pytest.mark.parametrize(
    "sample, pointer_size, indirect_count",
    [
        ("libadd.so", 8, 17),
        ("MachO64_x86-64_binary_large-bss.bin", 8, 3),
        ("MachO64_x86-64_binary_all.bin", 8, 4),
        ("macho-arm64-osx-chained-fixups.bin", 8, 2),
        ("FAT_MachO_arm-arm64-binary-helloworld.bin", 4, 53),
        ("FAT_MachO_x86-x86-64-binary_fatall.bin", 4, 4),
    ],
)
def test_string_pool_alignment(
    tmp_path: Path, sample: str, pointer_size: int, indirect_count: int
):
    fat = parse_macho(f"MachO/{sample}")
    original = fat.at(0)
    assert original is not None
    dynsym = original.dynamic_symbol_command

    assert dynsym is not None
    assert dynsym.nb_indirect_symbols == indirect_count

    symbols = sorted((s.name, s.value) for s in original.symbols)
    indirect_symbols = [(s.name, s.category) for s in dynsym.indirect_symbols]

    output = tmp_path / "aligned.macho"
    original.write(output)

    rebuilt_fat = lief.MachO.parse(output)
    assert rebuilt_fat is not None

    rebuilt = rebuilt_fat.at(0)
    assert rebuilt is not None

    symtab = rebuilt.symbol_command
    dynsym = rebuilt.dynamic_symbol_command

    assert symtab is not None
    assert dynsym is not None

    assert symtab.strings_offset % pointer_size == 0
    assert dynsym.nb_indirect_symbols == indirect_count

    assert sorted((s.name, s.value) for s in rebuilt.symbols) == symbols
    assert [(s.name, s.category) for s in dynsym.indirect_symbols] == indirect_symbols

    indirect_end = dynsym.indirect_symbol_offset + 4 * indirect_count
    padding = 4 if pointer_size == 8 and indirect_count % 2 else 0

    assert symtab.strings_offset == indirect_end + padding
    assert output.read_bytes()[indirect_end : symtab.strings_offset] == bytes(padding)

    checked, err = lief.MachO.check_layout(rebuilt)
    assert checked, err


@pytest.mark.private
def test_reject_misaligned_string_pool():
    malformed_fat = parse_macho("private/MachO/pr_1383.dylib")
    malformed = malformed_fat.at(0)
    assert malformed is not None

    checked, err = lief.MachO.check_layout(malformed)
    assert not checked
    assert "mis-aligned LINKEDIT content: SYMTAB_STR" in err
