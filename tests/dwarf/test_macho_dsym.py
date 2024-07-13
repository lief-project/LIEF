import lief
import pytest
from utils import get_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

def test_lief():
    macho = lief.MachO.parse(get_sample("private/DWARF/libLIEF.dylib")).at(0)

    dbg_info: lief.dwarf.DebugInfo = macho.debug_info
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 364

    elf_bin_cu = units[30]

    f1 = elf_bin_cu.find_function("_ZN4LIEF3ELF6Binary22add_dynamic_relocationERKNS0_10RelocationE")
    assert f1 is not None

    f1 = elf_bin_cu.find_function("LIEF::ELF::Binary::add_dynamic_relocation(LIEF::ELF::Relocation const&)")
    assert f1 is not None

    variables = list(f1.variables)
    assert len(variables) == 8
    assert variables[0].name == "None" # static Relocation None;
    assert variables[0].address == 0x370710
    assert variables[0].size == 80
