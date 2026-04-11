import lief
import pytest
from utils import get_debug_info, get_sample, parse_macho

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)


@pytest.mark.private
def test_lief():
    macho = parse_macho("private/DWARF/libLIEF.dylib").at(0)
    assert macho is not None

    dbg_info = get_debug_info(macho)
    assert isinstance(dbg_info, lief.dwarf.DebugInfo)

    units = list(dbg_info.compilation_units)
    assert len(units) == 364

    elf_bin_cu = units[30]
    assert elf_bin_cu is not None

    f1 = elf_bin_cu.find_function(
        "_ZN4LIEF3ELF6Binary22add_dynamic_relocationERKNS0_10RelocationE"
    )
    assert f1 is not None

    f1 = elf_bin_cu.find_function(
        "LIEF::ELF::Binary::add_dynamic_relocation(LIEF::ELF::Relocation const&)"
    )
    assert f1 is not None

    variables = list(f1.variables)
    assert len(variables) == 8
    var0 = variables[0]
    assert var0 is not None
    assert var0.name == "None"  # static Relocation None;
    assert var0.address == 0x370710
    assert var0.size == 80


def test_external_load():
    macho = parse_macho("DWARF/dSYM/example").at(0)
    assert macho is not None

    assert len(list(macho.disassemble("main"))) == 0
    macho.load_debug_info(
        get_sample("DWARF/dSYM/example.dSYM/Contents/Resources/DWARF/example")
    )

    assert len(list(macho.disassemble("main"))) == 375
