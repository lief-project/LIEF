import lief
from pathlib import Path
from utils import get_sample, check_layout

def test_dt_auxiliary(tmp_path: Path):
    lief.logging.enable_debug()
    elf = lief.ELF.parse(get_sample("ELF/libdt_auxiliary.so"))
    assert elf is not None

    aux_entry: lief.ELF.DynamicEntryAuxiliary = elf.get(lief.ELF.DynamicEntry.TAG.AUXILIARY)
    assert aux_entry is not None

    assert aux_entry.name == "libfoo.so"

    new_name = "libau" + 'x' * 200 + ".so"
    aux_entry.name = new_name
    out = tmp_path / "libaux.so"
    elf.write(out)

    new = lief.ELF.parse(out)
    check_layout(new)
    assert new.get(lief.ELF.DynamicEntry.TAG.AUXILIARY).name == new_name

def test_dt_filter(tmp_path: Path):
    lief.logging.enable_debug()
    elf = lief.ELF.parse(get_sample("ELF/libdt_auxiliary_filter.so"))
    assert elf is not None

    filter_entry: lief.ELF.DynamicEntryFilter = elf.get(lief.ELF.DynamicEntry.TAG.FILTER)
    assert isinstance(filter_entry, lief.ELF.DynamicEntryFilter)
    assert filter_entry is not None

    assert filter_entry.name == "libtoto.so"

    new_name = "lib" + "f" * 200 + "ilter.so"
    filter_entry.name = new_name
    out = tmp_path / "out.so"
    elf.write(out)

    new = lief.ELF.parse(out)
    check_layout(new)
    assert new.get(lief.ELF.DynamicEntry.TAG.FILTER).name == new_name
