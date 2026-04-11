import lief
import pytest
from utils import get_dsc_sample, has_dyld_shared_cache_samples

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

if not has_dyld_shared_cache_samples():
    pytest.skip("skipping: missing dyld shared cache files", allow_module_level=True)


def test_filename():
    dsc = lief.dsc.load(get_dsc_sample("ios-18.1"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e"

    dsc = lief.dsc.load(
        get_dsc_sample("ios-18.1/dyld_shared_cache_arm64e.62.dyldlinkedit")
    )
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e.62.dyldlinkedit"


def test_disassembler():
    dsc = lief.dsc.load(get_dsc_sample("ios-18.1"))
    assert dsc is not None
    assert dsc.filename == "dyld_shared_cache_arm64e"

    _main = dsc.main_cache
    assert _main is not None
    assert _main.filename == "dyld_shared_cache_arm64e"

    _subcache03 = dsc.find_subcache("dyld_shared_cache_arm64e.03")
    assert _subcache03 is not None
    assert _subcache03.load_address == 0x1854E8000

    _cache1 = dsc.cache_for_address(0x1886F4A44)
    assert _cache1 is not None
    assert _cache1.filename == "dyld_shared_cache_arm64e.03"
    _cache2 = dsc.cache_for_address(0x1886F4A44)
    assert _cache2 is not None
    assert _cache2.va_to_offset(0x1886F4A44) == 0x320CA44

    assert dsc.get_content_from_va(0x180000000, 8).hex(":") == "64:79:6c:64:5f:76:31:20"
    assert dsc.get_content_from_va(0x1886F3000, 8).hex(":") == "cf:fa:ed:fe:0c:00:00:01"
    assert dsc.get_content_from_va(0x1886F4A44, 8).hex(":") == "09:00:40:f9:28:00:40:f9"

    instructions = dsc.disassemble(0x1886F4A44)
    insts = [next(instructions) for _ in range(20)]
    _inst10 = insts[10]
    assert _inst10 is not None
    assert _inst10.opcode == lief.assembly.aarch64.OPCODE.RET  # type: ignore

    stub_island = dsc.disassemble(0x25CD2C0E0)
    stub_insts = [next(stub_island) for _ in range(20)]

    _si0 = stub_insts[0]
    assert _si0 is not None
    assert _si0.to_string() == "0x25cd2c0e0: adrp x16, #-3525632000"
    _si1 = stub_insts[1]
    assert _si1 is not None
    assert _si1.to_string() == "0x25cd2c0e4: add x16, x16, #3028"
    _si2 = stub_insts[2]
    assert _si2 is not None
    assert _si2.to_string() == "0x25cd2c0e8: br x16"
    _si3 = stub_insts[3]
    assert _si3 is not None
    assert _si3.to_string() == "0x25cd2c0ec: brk #0x1"
