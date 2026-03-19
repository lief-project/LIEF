import lief
import pytest

from utils import is_x86_64, get_sample

@pytest.mark.skipif(not is_x86_64(), reason="requires x86-64")
def test_hash():
    issue_863 = lief.ELF.parse(get_sample('ELF/issue_863.elf'))
    hello_c_debug = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_hello-c-debug.bin'))
    empty_gnu_hash = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_empty-gnu-hash.bin'))
    arm_ls = lief.ELF.parse(get_sample('ELF/ELF32_ARM_binary_ls.bin'))
    libfreebl3 = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_library_libfreebl3.so'))
    _test_897 = lief.ELF.parse(get_sample('ELF/test_897.elf'))
    etterlog = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))
    resolve = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_systemd-resolve.bin'))
    lib_symbol_versions = lief.ELF.parse(get_sample('ELF/lib_symbol_versions.so'))
    elf32_bin_all = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_all.bin'))

    assert hash(issue_863) > 0
    assert issue_863.sysv_hash is not None
    assert hash(issue_863.sysv_hash) > 0

    assert hello_c_debug.gnu_hash is not None
    assert hash(hello_c_debug.gnu_hash) > 0

    assert empty_gnu_hash[lief.ELF.DynamicEntry.TAG.FLAGS_1] is not None
    assert hash(empty_gnu_hash[lief.ELF.DynamicEntry.TAG.FLAGS_1]) > 0

    assert arm_ls[lief.ELF.DynamicEntry.TAG.FLAGS] is not None
    assert hash(arm_ls[lief.ELF.DynamicEntry.TAG.FLAGS]) > 0

    assert libfreebl3[lief.ELF.DynamicEntry.TAG.SONAME] is not None
    assert hash(libfreebl3[lief.ELF.DynamicEntry.TAG.SONAME]) > 0

    assert hello_c_debug[lief.ELF.DynamicEntry.TAG.GNU_HASH] is not None
    assert hash(hello_c_debug[lief.ELF.DynamicEntry.TAG.GNU_HASH]) > 0

    assert hello_c_debug[lief.ELF.DynamicEntry.TAG.INIT_ARRAY] is not None
    assert hash(hello_c_debug[lief.ELF.DynamicEntry.TAG.INIT_ARRAY]) > 0

    assert hello_c_debug[lief.ELF.DynamicEntry.TAG.NEEDED] is not None
    assert hash(hello_c_debug[lief.ELF.DynamicEntry.TAG.NEEDED]) > 0

    assert etterlog[lief.ELF.DynamicEntry.TAG.RPATH] is not None
    assert hash(etterlog[lief.ELF.DynamicEntry.TAG.RPATH]) > 0

    assert resolve[lief.ELF.DynamicEntry.TAG.RUNPATH] is not None
    assert hash(resolve[lief.ELF.DynamicEntry.TAG.RUNPATH]) > 0

    assert hash(resolve.header) > 0
    assert hash(etterlog.notes[0]) > 0
    assert hash(etterlog.notes[0]) > 0
    assert hash(etterlog.relocations[0]) > 0
    assert hash(etterlog.sections[0]) > 0
    assert hash(etterlog.segments[0]) > 0
    assert hash(etterlog.symbols_version[0]) > 0
    assert hash(lief.ELF.SymbolVersion.local) > 0

    assert hash(lib_symbol_versions.get_dynamic_symbol("foo").symbol_version.symbol_version_auxiliary) > 0
    assert hash(lib_symbol_versions.symbols_version_definition[0]) > 0
    assert hash(elf32_bin_all.symbols_version_requirement[0]) > 0
    assert hash(elf32_bin_all.symbols_version_requirement[0].get_auxiliary_symbols()[0]) > 0

def test_str(capsys):
    issue_863 = lief.ELF.parse(get_sample('ELF/issue_863.elf'))
    hello_c_debug = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_hello-c-debug.bin'))
    empty_gnu_hash = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_empty-gnu-hash.bin'))
    arm_ls = lief.ELF.parse(get_sample('ELF/ELF32_ARM_binary_ls.bin'))
    libfreebl3 = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_library_libfreebl3.so'))
    _test_897 = lief.ELF.parse(get_sample('ELF/test_897.elf'))
    etterlog = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_etterlog.bin'))
    resolve = lief.ELF.parse(get_sample('ELF/ELF64_x86-64_binary_systemd-resolve.bin'))
    lib_symbol_versions = lief.ELF.parse(get_sample('ELF/lib_symbol_versions.so'))
    elf32_bin_all = lief.ELF.parse(get_sample('ELF/ELF32_x86_binary_all.bin'))

    lief.logging.info(issue_863)
    assert issue_863.sysv_hash is not None
    lief.logging.info(issue_863.sysv_hash)

    assert hello_c_debug.gnu_hash is not None
    lief.logging.info(hello_c_debug.gnu_hash)

    assert empty_gnu_hash[lief.ELF.DynamicEntry.TAG.FLAGS_1] is not None
    lief.logging.info(empty_gnu_hash[lief.ELF.DynamicEntry.TAG.FLAGS_1])

    assert arm_ls[lief.ELF.DynamicEntry.TAG.FLAGS] is not None
    lief.logging.info(arm_ls[lief.ELF.DynamicEntry.TAG.FLAGS])

    assert libfreebl3[lief.ELF.DynamicEntry.TAG.SONAME] is not None
    lief.logging.info(libfreebl3[lief.ELF.DynamicEntry.TAG.SONAME])

    assert hello_c_debug[lief.ELF.DynamicEntry.TAG.GNU_HASH] is not None
    lief.logging.info(hello_c_debug[lief.ELF.DynamicEntry.TAG.GNU_HASH])


    assert hello_c_debug[lief.ELF.DynamicEntry.TAG.INIT_ARRAY] is not None
    lief.logging.info(hello_c_debug[lief.ELF.DynamicEntry.TAG.INIT_ARRAY])

    assert hello_c_debug[lief.ELF.DynamicEntry.TAG.NEEDED] is not None
    lief.logging.info(hello_c_debug[lief.ELF.DynamicEntry.TAG.NEEDED])

    assert etterlog[lief.ELF.DynamicEntry.TAG.RPATH] is not None
    lief.logging.info(etterlog[lief.ELF.DynamicEntry.TAG.RPATH])

    assert resolve[lief.ELF.DynamicEntry.TAG.RUNPATH] is not None
    lief.logging.info(resolve[lief.ELF.DynamicEntry.TAG.RUNPATH])

    lief.logging.info(resolve.header)
    lief.logging.info(etterlog.notes[0])
    lief.logging.info(etterlog.relocations[0])
    lief.logging.info(etterlog.sections[0])
    lief.logging.info(etterlog.segments[0])
    lief.logging.info(etterlog.symbols_version[0])
    lief.logging.info(lief.ELF.SymbolVersion.local)

    lief.logging.info(lib_symbol_versions.get_dynamic_symbol("foo").symbol_version.symbol_version_auxiliary)
    lief.logging.info(lib_symbol_versions.symbols_version_definition[0])
    lief.logging.info(elf32_bin_all.symbols_version_requirement[0])
    lief.logging.info(elf32_bin_all.symbols_version_requirement[0].get_auxiliary_symbols()[0])
