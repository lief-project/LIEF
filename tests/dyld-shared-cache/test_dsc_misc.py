import lief
import pytest

from utils import has_dyld_shared_cache_samples, get_dsc_sample

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

if not has_dyld_shared_cache_samples():
    pytest.skip("skipping: missing dyld shared cache files", allow_module_level=True)

def test_filename():
    dsc = lief.dsc.load(get_dsc_sample("ios-18.1"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e"

    dsc = lief.dsc.load(get_dsc_sample("ios-18.1/dyld_shared_cache_arm64e.62.dyldlinkedit"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e.62.dyldlinkedit"


def test_disassembler():
    dsc = lief.dsc.load(get_dsc_sample("ios-18.1"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e"

    assert dsc.main_cache.filename == "dyld_shared_cache_arm64e"

    assert dsc.find_subcache("dyld_shared_cache_arm64e.03").load_address == 0x1854e8000

    assert dsc.cache_for_address(0x1886f4a44).filename == "dyld_shared_cache_arm64e.03"
    assert dsc.cache_for_address(0x1886f4a44).va_to_offset(0x1886f4a44) == 0x320ca44

    assert dsc.get_content_from_va(0x180000000, 8).hex(':') == "64:79:6c:64:5f:76:31:20"
    assert dsc.get_content_from_va(0x1886f3000, 8).hex(':') == "cf:fa:ed:fe:0c:00:00:01"
    assert dsc.get_content_from_va(0x1886f4a44, 8).hex(':') == "09:00:40:f9:28:00:40:f9"

    instructions = dsc.disassemble(0x1886f4a44)
    insts = [next(instructions) for _ in range(20)]
    assert insts[10].opcode == lief.assembly.aarch64.OPCODE.RET

    stub_island = dsc.disassemble(0x25cd2c0e0)
    stub_insts = [next(stub_island) for _ in range(20)]

    assert stub_insts[0].to_string() == "0x25cd2c0e0: adrp x16, #-3525632000"
    assert stub_insts[1].to_string() == "0x25cd2c0e4: add x16, x16, #3028"
    assert stub_insts[2].to_string() == "0x25cd2c0e8: br x16"
    assert stub_insts[3].to_string() == "0x25cd2c0ec: brk #0x1"
