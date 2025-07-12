import pytest
import subprocess

import lief
from pathlib import Path
from subprocess import Popen

from utils import get_sample, is_linux, is_x86_64

def test_issue_749():
    lib_path = get_sample('ELF/lib_symbol_versions.so')
    lib: lief.ELF.Binary = lief.parse(lib_path)
    sym = lib.get_dynamic_symbol("foo")
    assert sym.symbol_version.symbol_version_auxiliary.name == "LIBFOO_2.0"

def test_issue_1014(tmp_path: Path):
    lib_path = get_sample('ELF/libfoo_issue_1014.so')
    lib: lief.ELF.Binary = lief.parse(lib_path)
    def check_lib(lib: lief.ELF.Binary):
        svd = lib.symbols_version_definition
        assert len(svd) == 6

        assert len(svd[0].auxiliary_symbols) == 1
        assert svd[0].auxiliary_symbols[0].name == "libfoo.so"

        assert len(svd[1].auxiliary_symbols) == 1
        assert svd[1].auxiliary_symbols[0].name == "LIBFOO_1.0"

        assert len(svd[2].auxiliary_symbols) == 2
        assert svd[2].auxiliary_symbols[0].name == "LIBFOO_2.0"
        assert svd[2].auxiliary_symbols[1].name == "LIBFOO_1.0"

        assert len(svd[3].auxiliary_symbols) == 2
        assert svd[3].auxiliary_symbols[0].name == "LIBFOO_3.0"
        assert svd[3].auxiliary_symbols[1].name == "LIBFOO_2.0"

        assert len(svd[4].auxiliary_symbols) == 1
        assert svd[4].auxiliary_symbols[0].name == "LIBBAR_1.0"

        assert len(svd[5].auxiliary_symbols) == 2
        assert svd[5].auxiliary_symbols[0].name == "LIBBAR_2.0"
        assert svd[5].auxiliary_symbols[1].name == "LIBBAR_1.0"
    check_lib(lib)

    out = tmp_path / "libfoo_issue_1014.so"
    lib.write(out.as_posix())
    new_lib = lief.ELF.parse(out.as_posix())
    check_lib(new_lib)

def test_remove_symbol(tmp_path: Path):
    elf = lief.ELF.parse(get_sample('ELF/lib_symbol_versions.so'))

    sym: lief.ELF.Symbol = elf.get_symbol("puts")

    version: lief.ELF.SymbolVersion = sym.symbol_version
    assert version is not None
    assert str(version) == "GLIBC_2.2.5(4)"
    version.as_global()

    output = tmp_path / "lib_symbol_versions.so"

    elf.write(output.as_posix())

    new = lief.ELF.parse(output)
    assert str(new.get_symbol("puts").symbol_version) == "* Global *"

def test_remove_all_version(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/ELF64_x86-64_binary_all.bin"))
    to_delete = set()
    for s in elf.symbols:
        version = s.symbol_version
        if version is None:
            continue
        aux = version.symbol_version_auxiliary
        if aux is None or not aux.name.startswith("GLIBC_"):
            continue

        to_delete.add(aux.name)
        version.as_global()

    for req in elf.symbols_version_requirement:
        for version in to_delete:
            req.remove_aux_requirement(version)

    out = tmp_path / "out.elf"
    elf.write(out.as_posix())

    new = lief.ELF.parse(out)
    assert new.get_symbol("__libc_start_main").symbol_version.symbol_version_auxiliary is None
    assert new.find_version_requirement("libc.so.6") is None
    out.chmod(0o755)

    if is_linux() and is_x86_64():
        with Popen([out.as_posix()], universal_newlines=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert "Hello World: 1" in stdout


def test_remove_req(tmp_path: Path):
    elf = lief.ELF.parse(get_sample("ELF/test_897.elf"))
    assert len(elf.symbols_version_requirement) == 2
    assert elf.symbols_version_requirement[0].name == "libm.so.6"
    assert elf.symbols_version_requirement[1].name == "libc.so.6"

    assert elf.remove_version_requirement("libm.so.6")

    out = tmp_path / "out.elf"
    elf.write(out.as_posix())

    new = lief.ELF.parse(out)

    assert new.find_version_requirement("libm.so.6") is None
    assert new.find_version_requirement("libc.so.6") is not None

    assert len(new.symbols_version_requirement) == 1

    out.chmod(0o755)

    if is_linux() and is_x86_64():
        with Popen([out.as_posix()], universal_newlines=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert "fun6!" in stdout
