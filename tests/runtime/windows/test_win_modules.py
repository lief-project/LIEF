from enum import StrEnum, auto
from pathlib import Path

import lief
import pytest
from utils import check_attributes, check_layout, disable_logging


class MemoryFix(StrEnum):
    FIX = auto()
    SKIP = auto()


if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.WINDOWS:
    pytest.skip("skipping: windows only", allow_module_level=True)


@pytest.mark.runtime
def test_list_modules():
    modules = [m for m in lief.runtime.modules() if m is not None]
    assert len(modules) > 0

    assert all(m.imagebase > 0 for m in modules)
    assert all(isinstance(m, lief.runtime.windows.Module) for m in modules)

    lief_module = [m for m in modules if m.name in {"_lief.pyd", "_lief_extended.pyd"}]
    assert len(lief_module) == 1
    assert len(lief_module[0].path) > 0
    assert lief_module[0].size > 0
    assert isinstance(lief_module[0], lief.runtime.windows.Module)
    assert lief_module[0].handle is not None


@pytest.mark.parametrize(
    "fix",
    [
        MemoryFix.FIX,
        MemoryFix.SKIP,
    ],
)
@pytest.mark.runtime
@disable_logging
def test_load_library(tmp_path: Path, fix: MemoryFix):
    must_fix = fix == MemoryFix.FIX
    modules = [m for m in lief.runtime.modules() if m is not None]
    lief_module = [m for m in modules if m.name in {"_lief.pyd", "_lief_extended.pyd"}]
    assert len(lief_module) == 1
    module_name = lief_module[0].name

    mod = lief.runtime.windows.dlopen(module_name)
    assert mod is not None

    assert mod.imagebase == lief_module[0].imagebase

    with lief.logging.level_scope(lief.logging.Level.Info):
        lief.logging.info(f"Imagebase: {mod.imagebase:#010x}")

    config = lief.PE.ParserConfig()
    if fix == MemoryFix.FIX:
        config.rebase = 0x180000000
    memory_mod = mod.parse_from_memory(config)
    assert memory_mod is not None
    file_mod = mod.parse_from_path()
    assert file_mod is not None

    assert memory_mod.dos_header == file_mod.dos_header
    assert memory_mod.header == file_mod.header

    if fix == MemoryFix.SKIP:
        assert memory_mod.optional_header.imagebase == lief_module[0].imagebase

    check_attributes(
        memory_mod.optional_header,
        file_mod.optional_header,
        skip_list=("imagebase",),
        skip_cond=must_fix,
    )

    assert len(memory_mod.sections) == len(file_mod.sections)
    for lhs, rhs in zip(memory_mod.sections, file_mod.sections):
        check_attributes(lhs, rhs, skip_list=("padding", "content", "entropy"))

    assert memory_mod.dos_stub == file_mod.dos_stub

    check_attributes(
        memory_mod.sections,
        file_mod.sections,
        skip_list=("padding", "content", "entropy"),
    )

    check_attributes(memory_mod.exceptions, file_mod.exceptions)

    check_attributes(
        memory_mod.data_directories,
        file_mod.data_directories,
        skip_list=("section", "content"),
    )

    check_attributes(memory_mod.debug, file_mod.debug, skip_list=("section",))

    check_attributes(
        memory_mod.get_export(), file_mod.get_export(), skip_list=("entries",)
    )

    mem_export = memory_mod.get_export()
    file_export = file_mod.get_export()
    assert mem_export is not None
    assert file_export is not None
    check_attributes(
        mem_export.entries,
        file_export.entries,
        skip_list=("forward_information", "demangled_name"),
    )

    check_attributes(memory_mod.imports, file_mod.imports, skip_list=("entries",))

    check_attributes(memory_mod.imports, file_mod.imports, skip_list=("entries",))

    for L, R in zip(memory_mod.imports, file_mod.imports):
        check_attributes(
            L.entries, R.entries, skip_list=("iat_value"), skip_cond=must_fix
        )

    check_attributes(
        memory_mod.relocations, file_mod.relocations, skip_list=("entries")
    )

    for L, R in zip(memory_mod.relocations, file_mod.relocations):
        check_attributes(L.entries, R.entries, skip_list=())
    check_attributes(
        memory_mod.load_configuration,
        file_mod.load_configuration,
        skip_list=(
            "cast_guard_os_determined_failure_mode",
            "guard_address_taken_iat_entries",
            "guard_cf_check_function_pointer",
            "guard_cf_dispatch_function_pointer",
            "guard_cf_functions",
            "guard_eh_continuation_functions",
            "guard_long_jump_targets",
            "guard_memcpy_function_pointer",
            "guard_xfg_check_function_pointer",
            "guard_xfg_dispatch_function_pointer",
            "guard_xfg_table_dispatch_function_pointer",
            "security_cookie",
        ),
        skip_cond=must_fix,
    )

    out = tmp_path / f"new_{module_name}"
    memory_mod.write(out)
    check_layout(memory_mod)
