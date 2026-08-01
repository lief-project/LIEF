from pathlib import Path

import lief
import pytest
from utils import align, check_attributes, disable_logging, resolve_runtime_library

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.OSX:
    pytest.skip("skipping: osx only", allow_module_level=True)


@pytest.mark.runtime
def test_list_modules():
    modules = [m for m in lief.runtime.modules() if m is not None]
    assert len(modules) > 0

    assert all(m.imagebase > 0 for m in modules)
    assert all(isinstance(m, lief.runtime.osx.Module) for m in modules)

    lief_module = [m for m in modules if m.name in {"_lief.so", "_lief_extended.so"}]
    assert len(lief_module) == 1
    assert len(lief_module[0].path) > 0
    assert lief_module[0].size > 0


@pytest.mark.runtime
@disable_logging
def test_load_library():
    modules = [m for m in lief.runtime.modules() if m is not None]
    lief_module = [m for m in modules if m.name in {"_lief.so", "_lief_extended.so"}]
    assert len(lief_module) == 1
    module_name = lief_module[0].name
    assert module_name != ""

    with lief.logging.level_scope(lief.logging.Level.Debug):
        mod = lief.runtime.osx.dlopen(lief_module[0].path)
    assert mod is not None

    assert mod.imagebase == lief_module[0].imagebase


@pytest.mark.runtime
@disable_logging
def test_dlopen():
    library = resolve_runtime_library("runtime-simple-lib")

    fat = lief.MachO.parse(library)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None
    mod = lief.runtime.osx.dlopen(library)
    assert mod is not None
    assert mod.name == library.name
    assert align(mod.end - mod.imagebase, macho.page_size) == macho.virtual_size
    assert mod.path == library.as_posix()


@pytest.mark.runtime
@disable_logging
def test_parse_from_memory(tmp_path: Path):
    library = resolve_runtime_library("runtime-simple-lib")

    fat = lief.MachO.parse(library)
    assert fat is not None
    macho = fat.at(0)
    assert macho is not None
    mod = lief.runtime.osx.dlopen(library)
    assert mod is not None

    config = lief.MachO.ParserConfig.deep
    fat_mem = lief.MachO.parse_from_memory(mod.imagebase, config)
    assert fat_mem is not None
    mem = fat_mem.at(0)
    assert mem is not None

    assert mem.imagebase == macho.imagebase
    assert mem.virtual_size == macho.virtual_size

    check_attributes(mem.header, macho.header)
    check_attributes(mem.libraries, macho.libraries)
    check_attributes(mem.symbols, macho.symbols)
    check_attributes(mem.sections, macho.sections, skip_list=["segment", "entropy"])
    check_attributes(mem.dyld_chained_fixups, macho.dyld_chained_fixups)
    check_attributes(mem.function_starts, macho.function_starts)
    check_attributes(mem.rpaths, macho.rpaths)

    output = tmp_path / f"mem_{library.name}"
    mem.write(output)
    lief.logging.info(f"Library written here: {output}")
    from_mem = lief.MachO.parse(output)
    assert from_mem is not None
    check, msg = lief.MachO.check_layout(from_mem)
    assert check, msg
