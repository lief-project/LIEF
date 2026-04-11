from utils import parse_elf


def test_symbols():
    target = parse_elf("ELF/ELF32_x86_library_libshellx.so")
    symbols = [
        sym
        for idx, sym in enumerate(target.dynamic_symbols)
        if idx == 0 or len(sym.name) > 0
    ]
    assert len(symbols) == 48

    assert symbols[2].name == "__cxa_atexit"


def test_relocations():
    target = parse_elf("ELF/ELF32_x86_library_libshellx.so")
    relocations = target.relocations
    assert len(relocations) == 47

    assert relocations[10].symbol is not None
    assert relocations[10].symbol.name == "strlen"
