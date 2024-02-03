import lief
from utils import get_sample
from pathlib import Path

def test_chrome_arm64(tmp_path: Path):
    chrome_sample = Path(get_sample("ELF/libmonochrome-arm64.so"))
    chrome = lief.ELF.parse(chrome_sample)
    assert lief.ELF.DynamicEntry.TAG.AARCH64_BTI_PLT in chrome

    packed_relocs = [r for r in chrome.dynamic_relocations if r.is_android_packed]
    assert len(packed_relocs) == 145599

    assert packed_relocs[0].address == 0x6426910
    assert packed_relocs[0].addend == 0x6426910
    assert packed_relocs[0].type == lief.ELF.Relocation.TYPE.AARCH64_RELATIVE

    assert packed_relocs[145576].address == 0x65e3598
    assert packed_relocs[145576].addend == 0
    assert packed_relocs[145576].symbol.name == "memfd_create"
    assert packed_relocs[145576].type == lief.ELF.Relocation.TYPE.AARCH64_GLOB_DAT

    assert packed_relocs[145598].address == 0x6646a48
    assert packed_relocs[145598].addend == 0
    assert packed_relocs[145598].symbol.name == "ioctl"
    assert packed_relocs[145598].type == lief.ELF.Relocation.TYPE.AARCH64_ABS64

    out_simple = tmp_path / "chrome_simple.so"
    chrome.write(out_simple.as_posix())
    original_size = chrome_sample.stat().st_size
    new_size = out_simple.stat().st_size
    assert new_size <= original_size

    new = lief.ELF.parse(out_simple.as_posix())

    new_packed_relocs = [r for r in new.dynamic_relocations if r.is_android_packed]
    assert len(new_packed_relocs) == 145599

    assert new_packed_relocs[0].address == 0x6426910
    assert new_packed_relocs[0].addend == 0x6426910
    assert new_packed_relocs[0].type == lief.ELF.Relocation.TYPE.AARCH64_RELATIVE

    assert new_packed_relocs[145576].address == 0x65e3598
    assert new_packed_relocs[145576].addend == 0
    assert new_packed_relocs[145576].symbol.name == "memfd_create"
    assert new_packed_relocs[145576].type == lief.ELF.Relocation.TYPE.AARCH64_GLOB_DAT

    assert new_packed_relocs[145598].address == 0x6646a48
    assert new_packed_relocs[145598].addend == 0
    assert new_packed_relocs[145598].symbol.name == "ioctl"
    assert new_packed_relocs[145598].type == lief.ELF.Relocation.TYPE.AARCH64_ABS64

    chrome_mod = lief.ELF.parse(chrome_sample)
    chrome_mod_out = tmp_path / "chrome_mod.so"
    builder = lief.ELF.Builder(chrome_mod)
    builder.config.force_relocate = True
    builder.build()
    builder.write(chrome_mod_out.as_posix())
    assert abs(chrome_mod_out.stat().st_size - original_size) < 0x5cf000

    chrome_mod = lief.ELF.parse(chrome_mod_out)

    mod_packed_relocs = [r for r in chrome_mod.dynamic_relocations if r.is_android_packed]
    assert len(mod_packed_relocs) == 145599

    assert mod_packed_relocs[0].address == 0x6426910 + 0x1000
    assert mod_packed_relocs[0].addend == 0x6426910 + 0x1000
    assert mod_packed_relocs[0].type == lief.ELF.Relocation.TYPE.AARCH64_RELATIVE

    assert mod_packed_relocs[145576].address == 0x65e3598 + 0x1000
    assert mod_packed_relocs[145576].addend == 0
    assert mod_packed_relocs[145576].symbol.name == "memfd_create"
    assert mod_packed_relocs[145576].type == lief.ELF.Relocation.TYPE.AARCH64_GLOB_DAT

    assert mod_packed_relocs[145598].address == 0x6646a48 + 0x1000
    assert mod_packed_relocs[145598].addend == 0
    assert mod_packed_relocs[145598].symbol.name == "ioctl"
    assert mod_packed_relocs[145598].type == lief.ELF.Relocation.TYPE.AARCH64_ABS64


def test_chrome_armv7(tmp_path: Path):
    chrome_sample = Path(get_sample("ELF/libmonochrome-armv7.so"))
    chrome = lief.ELF.parse(chrome_sample)

    packed_relocs = [r for r in chrome.dynamic_relocations if r.is_android_packed]
    assert len(packed_relocs) == 513897

    assert packed_relocs[0].address == 0x471b14c
    assert packed_relocs[0].addend == 0
    assert packed_relocs[0].type == lief.ELF.Relocation.TYPE.ARM_RELATIVE

    assert packed_relocs[513855].address == 0x49bbad0
    assert packed_relocs[513855].addend == 0
    assert packed_relocs[513855].symbol.name == "android_fdsan_exchange_owner_tag"
    assert packed_relocs[513855].type == lief.ELF.Relocation.TYPE.ARM_GLOB_DAT

    assert packed_relocs[513896].address == 0x49fd61c
    assert packed_relocs[513896].addend == 0
    assert packed_relocs[513896].symbol.name == "ioctl"
    assert packed_relocs[513896].type == lief.ELF.Relocation.TYPE.ARM_ABS32

    out_simple = tmp_path / "chrome_simple.so"
    chrome.write(out_simple.as_posix())
    original_size = chrome_sample.stat().st_size
    new_size = out_simple.stat().st_size
    assert new_size <= original_size

    new = lief.ELF.parse(out_simple.as_posix())

    new_packed_relocs = [r for r in new.dynamic_relocations if r.is_android_packed]
    assert len(new_packed_relocs) == 513897

    assert new_packed_relocs[0].address == 0x471b14c
    assert new_packed_relocs[0].addend == 0
    assert new_packed_relocs[0].type == lief.ELF.Relocation.TYPE.ARM_RELATIVE

    assert new_packed_relocs[513855].address == 0x49bbad0
    assert new_packed_relocs[513855].addend == 0
    assert new_packed_relocs[513855].symbol.name == "android_fdsan_exchange_owner_tag"
    assert new_packed_relocs[513855].type == lief.ELF.Relocation.TYPE.ARM_GLOB_DAT

    assert new_packed_relocs[513896].address == 0x49fd61c
    assert new_packed_relocs[513896].addend == 0
    assert new_packed_relocs[513896].symbol.name == "ioctl"
    assert new_packed_relocs[513896].type == lief.ELF.Relocation.TYPE.ARM_ABS32

    chrome_mod = lief.ELF.parse(chrome_sample)
    chrome_mod_out = tmp_path / "chrome_mod.so"
    builder = lief.ELF.Builder(chrome_mod)
    builder.config.force_relocate = True
    builder.build()
    builder.write(chrome_mod_out.as_posix())
    assert abs(chrome_mod_out.stat().st_size - original_size) < 0x5cf000

    chrome_mod = lief.ELF.parse(chrome_mod_out)

    mod_packed_relocs = [r for r in chrome_mod.dynamic_relocations if r.is_android_packed]
    assert len(mod_packed_relocs) == 513897

    assert mod_packed_relocs[0].address == 0x471b14c + 0x1000
    assert mod_packed_relocs[0].addend == 0
    assert mod_packed_relocs[0].type == lief.ELF.Relocation.TYPE.ARM_RELATIVE

    assert mod_packed_relocs[513855].address == 0x49bbad0 + 0x1000
    assert mod_packed_relocs[513855].addend == 0
    assert mod_packed_relocs[513855].symbol.name == "android_fdsan_exchange_owner_tag"
    assert mod_packed_relocs[513855].type == lief.ELF.Relocation.TYPE.ARM_GLOB_DAT

    assert mod_packed_relocs[513896].address == 0x49fd61c + 0x1000
    assert mod_packed_relocs[513896].addend == 0
    assert mod_packed_relocs[513896].symbol.name == "ioctl"
    assert mod_packed_relocs[513896].type == lief.ELF.Relocation.TYPE.ARM_ABS32
