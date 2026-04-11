from pathlib import Path
from typing import cast

import lief
from utils import check_layout, parse_elf


def test_dt_auxiliary(tmp_path: Path):
    lief.logging.enable_debug()
    elf = parse_elf("ELF/libdt_auxiliary.so")
    assert elf is not None

    aux_entry = cast(
        lief.ELF.DynamicEntryAuxiliary, elf.get(lief.ELF.DynamicEntry.TAG.AUXILIARY)
    )
    assert aux_entry is not None

    assert aux_entry.name == "libfoo.so"

    new_name = "libau" + "x" * 200 + ".so"
    aux_entry.name = new_name
    out = tmp_path / "libaux.so"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None
    check_layout(new)
    aux_result = cast(
        lief.ELF.DynamicEntryAuxiliary, new.get(lief.ELF.DynamicEntry.TAG.AUXILIARY)
    )
    assert aux_result is not None
    assert aux_result.name == new_name


def test_dt_filter(tmp_path: Path):
    lief.logging.enable_debug()
    elf = parse_elf("ELF/libdt_auxiliary_filter.so")
    assert elf is not None

    filter_entry = cast(
        lief.ELF.DynamicEntryFilter, elf.get(lief.ELF.DynamicEntry.TAG.FILTER)
    )
    assert isinstance(filter_entry, lief.ELF.DynamicEntryFilter)
    assert filter_entry is not None

    assert filter_entry.name == "libtoto.so"

    new_name = "lib" + "f" * 200 + "ilter.so"
    filter_entry.name = new_name
    out = tmp_path / "out.so"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None
    check_layout(new)
    filter_result = cast(
        lief.ELF.DynamicEntryFilter, new.get(lief.ELF.DynamicEntry.TAG.FILTER)
    )
    assert filter_result is not None
    assert filter_result.name == new_name
