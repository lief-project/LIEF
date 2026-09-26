import subprocess
import sys
from pathlib import Path
from subprocess import Popen
from typing import cast

import lief
import pytest
from utils import (
    address_space_limiter,
    check_layout,
    get_sample,
    is_linux,
    is_x86_64,
    parse_elf,
)


def test_issue_749():
    lib_path = get_sample("ELF/lib_symbol_versions.so")
    lib = cast(lief.ELF.Binary, lief.parse(lib_path))
    sym = lib.get_dynamic_symbol("foo")
    assert sym is not None
    assert sym.symbol_version is not None
    assert sym.symbol_version.symbol_version_auxiliary is not None
    assert sym.symbol_version.symbol_version_auxiliary.name == "LIBFOO_2.0"


def test_issue_1014(tmp_path: Path):
    lib_path = get_sample("ELF/libfoo_issue_1014.so")
    lib = parse_elf(lib_path)

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
    lib.write(out)
    new_lib = lief.ELF.parse(out)
    assert new_lib is not None
    check_lib(new_lib)


def test_versym_hidden(tmp_path: Path):
    elf = parse_elf("ELF/ELF32_x86_binary_all.bin")
    symbol = elf.get_dynamic_symbol("first")
    assert symbol is not None

    version = symbol.symbol_version
    assert version is not None
    assert version.value == 0x8002
    assert version.version == 2
    assert version.is_hidden
    assert not version.is_local
    assert not version.is_global

    version.is_hidden = False
    assert version.value == 2
    assert not version.is_hidden
    assert version.symbol_version_auxiliary is not None

    output = tmp_path / "versym-hidden.elf"
    elf.write(output)

    reparsed = parse_elf(output)
    symbol = reparsed.get_dynamic_symbol("first")
    assert symbol is not None
    version = symbol.symbol_version
    assert version is not None
    assert version.value == 2
    assert version.version == 2
    assert not version.is_hidden
    assert version.symbol_version_auxiliary is not None

    version.is_hidden = True
    assert version.value == 0x8002
    assert version.is_hidden

    version.as_global()
    assert version.value == 1
    assert version.is_global
    assert not version.is_hidden

    version.is_hidden = True
    assert version.value == 0x8001
    assert version.is_global
    assert version.is_hidden

    version.as_local()
    assert version.value == 0
    assert version.is_local
    assert not version.is_hidden


def test_remove_symbol(tmp_path: Path):
    elf = parse_elf("ELF/lib_symbol_versions.so")

    sym = cast(lief.ELF.Symbol, elf.get_symbol("puts"))

    version = cast(lief.ELF.SymbolVersion, sym.symbol_version)
    assert version is not None
    assert str(version) == "GLIBC_2.2.5(4)"
    version.as_global()

    output = tmp_path / "lib_symbol_versions.so"

    elf.write(output)
    check_layout(elf)

    new = lief.ELF.parse(output)
    assert new is not None
    symbol = cast(lief.ELF.Symbol, new.get_symbol("puts"))
    assert str(symbol.symbol_version) == "* Global *"


def test_remove_all_version(tmp_path: Path):
    elf = parse_elf("ELF/ELF64_x86-64_binary_all.bin")
    to_delete = set()
    for s in elf.symbols:
        version = s.symbol_version
        if version is None:
            continue
        aux = version.symbol_version_auxiliary
        aux_name = aux.name if aux is not None else None
        if (
            aux is None
            or not isinstance(aux_name, str)
            or not aux_name.startswith("GLIBC_")
        ):
            continue

        to_delete.add(aux.name)
        version.as_global()

    for req in elf.symbols_version_requirement:
        for version in to_delete:
            req.remove_aux_requirement(str(version))

    out = tmp_path / "out.elf"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None
    check_layout(new)
    libc_start_main = new.get_symbol("__libc_start_main")
    assert libc_start_main is not None
    assert libc_start_main.symbol_version is not None  # type: ignore
    assert libc_start_main.symbol_version.symbol_version_auxiliary is None  # type: ignore
    assert new.find_version_requirement("libc.so.6") is None
    out.chmod(0o755)

    if is_linux() and is_x86_64():
        with Popen(
            [out.as_posix()],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            proc.poll()
            assert "Hello World: 1" in stdout


def test_remove_req(tmp_path: Path):
    elf = parse_elf("ELF/test_897.elf")
    assert len(elf.symbols_version_requirement) == 2
    assert elf.symbols_version_requirement[0].name == "libm.so.6"
    assert elf.symbols_version_requirement[1].name == "libc.so.6"

    assert elf.remove_version_requirement("libm.so.6")

    out = tmp_path / "out.elf"
    elf.write(out)

    new = lief.ELF.parse(out)
    assert new is not None

    assert new.find_version_requirement("libm.so.6") is None
    assert new.find_version_requirement("libc.so.6") is not None

    assert len(new.symbols_version_requirement) == 1

    out.chmod(0o755)

    if is_linux() and is_x86_64():
        with Popen(
            [out.as_posix()],
            universal_newlines=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            proc.poll()
            assert "fun6!" in stdout


@pytest.mark.private
def test_verneed_vn_next_wrap_bounded():
    sample = get_sample("private/ELF/verneed_vn_next.elf")

    elf = lief.ELF.parse(sample)
    assert elf is not None
    assert len(elf.symbols_version_requirement) <= 2


@pytest.mark.private
def test_verneed_vna_next_wrap_bounded():
    sample = get_sample("private/ELF/verneed_vna_next.elf")

    elf = lief.ELF.parse(sample)
    assert elf is not None
    reqs = elf.symbols_version_requirement
    assert len(reqs) == 1
    assert len(reqs[0].get_auxiliary_symbols()) <= 2


@pytest.mark.linux
@pytest.mark.private
def test_verneed_next_wrap_no_oom():
    sample = Path(get_sample("private/ELF/verneed_combined.elf")).absolute()

    subprocess.check_call(
        [sys.executable, "-c", f'import lief; lief.parse(r"{sample}")'],
        timeout=60.0,
        preexec_fn=address_space_limiter(),
    )


@pytest.mark.private
def test_capped_verdef():
    sample = get_sample("private/ELF/verdef_num.elf")
    elf = lief.ELF.parse(sample)
    assert elf is not None
    assert len(elf.symbols_version_definition) == 1_000_000
