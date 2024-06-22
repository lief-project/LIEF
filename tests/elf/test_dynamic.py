#!/usr/bin/env python
import os
import stat
import subprocess
import pytest
from subprocess import Popen
from typing import List
from pathlib import Path

import lief
from utils import get_compiler, is_linux

if not is_linux():
    pytest.skip("requires Linux", allow_module_level=True)

lief.logging.set_level(lief.logging.LEVEL.WARN)

COMPILER = get_compiler()

LIBADD_C = """\
#include <stdlib.h>
#include <stdio.h>

int add(int a, int b);

int add(int a, int b) {
  printf("%d + %d = %d\\n", a, b, a + b);
  return a + b;
}
"""

BINADD_C = """\
#include <stdio.h>
#include <stdlib.h>

int add(int a, int b);

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <a> <b>\\n", argv[0]);
    exit(-1);
  }

  int res = add(atoi(argv[1]), atoi(argv[2]));
  printf("From myLIb, a + b = %d\\n", res);
  return 0;
}
"""


def compile_libadd(out: Path, infile: Path, extra_flags: List[str]):
    CC_FLAGS = ['-fPIC', '-shared', '-Wl,-soname,libadd.so'] + extra_flags
    cmd = [COMPILER, '-o', out] + CC_FLAGS + [infile]
    print("Compile 'libadd' with: {}".format(" ".join(map(str, cmd))))

    with Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=out.parent) as P:
        stdout = P.stdout.read().decode('utf8')
        print(stdout)

def compile_binadd(out: Path, infile: Path, extra_flags: List[str]):
    CC_FLAGS = ['-fPIC', '-pie', '-L', out.parent] + extra_flags
    cmd = [COMPILER, '-o', out] + CC_FLAGS + [infile, '-ladd']
    print("Compile 'libadd' with: {}".format(" ".join(map(str, cmd))))

    with Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=out.parent) as P:
        stdout = P.stdout.read().decode('utf8')
        print(stdout)


@pytest.mark.skipif(not is_linux(), reason="requires Linux")
@pytest.mark.parametrize("style", [
    ("sysv", False),
    ("both", True),
    ("gnu",  True),
])
def test_add_dynamic_symbols(tmp_path: Path, style):
    hash_style, symbol_sorted = style
    link_opt = f"-Wl,--hash-style={hash_style}"

    binadd_c = tmp_path / "binadd.c"
    libadd_c = tmp_path / "libadd.c"

    binadd_bin = tmp_path / "binadd.bin"
    libadd_so  = tmp_path / "libadd.so"

    binadd_c.write_text(BINADD_C)
    libadd_c.write_text(LIBADD_C)

    compile_libadd(libadd_so, libadd_c, [link_opt])
    compile_binadd(binadd_bin, binadd_c, [link_opt])

    libadd = lief.ELF.parse(libadd_so.as_posix())

    dynamic_symbols = list(libadd.dynamic_symbols)
    for sym in dynamic_symbols:
        libadd.add_dynamic_symbol(sym)
    dynamic_section = libadd.get_section(".dynsym")
    libadd.extend(dynamic_section, dynamic_section.entry_size * len(dynamic_symbols))
    if hash_style != "gnu":
        hash_section = libadd.get_section(".hash")
        libadd.extend(hash_section, hash_section.entry_size * len(dynamic_symbols))
    libadd.write(libadd_so.as_posix())

    opt = {
      'stdout': subprocess.PIPE,
      'stderr': subprocess.STDOUT,
      'env'   : {"LD_LIBRARY_PATH": tmp_path.as_posix()}
    }

    with Popen([binadd_bin, '1', '2'], **opt) as P: # type: ignore
        stdout = P.stdout.read().decode("utf8")
        P.communicate()
        assert P.returncode == 0
        assert "From myLIb, a + b = 3" in stdout

    libadd = lief.ELF.parse(libadd_so.as_posix())
    dynamic_section = libadd.get_section(".dynsym")
    # TODO: Size of libadd.dynamic_symbols is larger than  dynamic_symbols_size.
    dynamic_symbols_size = int(dynamic_section.size / dynamic_section.entry_size)
    dynamic_symbols = list(libadd.dynamic_symbols)[:dynamic_symbols_size]
    if symbol_sorted:
        first_not_null_symbol_index = dynamic_section.information
        first_exported_symbol_index = next(i for i, sym in enumerate(dynamic_symbols) if sym.shndx != 0)

        assert all(map(lambda sym: sym.shndx == 0 and sym.binding == lief.ELF.Symbol.BINDING.LOCAL,
                       dynamic_symbols[:first_not_null_symbol_index]))

        assert (all(map(lambda sym: sym.shndx == 0 and sym.binding != lief.ELF.Symbol.BINDING.LOCAL,
                        dynamic_symbols[first_not_null_symbol_index:first_exported_symbol_index])))

        assert (all(map(lambda sym: sym.shndx != 0, dynamic_symbols[first_exported_symbol_index:])))

@pytest.mark.skipif(not is_linux(), reason="requires Linux")
def test_remove_library(tmp_path: Path):
    binadd_c = tmp_path / "binadd.c"
    libadd_c = tmp_path / "libadd.c"

    binadd_bin = tmp_path / "binadd.bin"
    libadd_so  = tmp_path / "libadd.so"

    binadd_c.write_text(BINADD_C)
    libadd_c.write_text(LIBADD_C)

    compile_libadd(libadd_so, libadd_c, [])
    compile_binadd(binadd_bin, binadd_c, [])

    binadd = lief.ELF.parse(binadd_bin.as_posix())

    libadd_needed = binadd.get_library("libadd.so")
    binadd -= libadd_needed
    assert not binadd.has_library("libadd.so")


@pytest.mark.skipif(not is_linux(), reason="requires Linux")
def test_remove_tag(tmp_path: Path):
    binadd_c = tmp_path / "binadd.c"
    libadd_c = tmp_path / "libadd.c"

    binadd_bin = tmp_path / "binadd.bin"
    libadd_so  = tmp_path / "libadd.so"

    binadd_c.write_text(BINADD_C)
    libadd_c.write_text(LIBADD_C)

    compile_libadd(libadd_so, libadd_c, [])
    compile_binadd(binadd_bin, binadd_c, [])

    binadd = lief.ELF.parse(binadd_bin.as_posix())

    binadd -= lief.ELF.DynamicEntry.TAG.NEEDED
    assert all(e.tag != lief.ELF.DynamicEntry.TAG.NEEDED for e in binadd.dynamic_entries)

@pytest.mark.skipif(not is_linux(), reason="requires Linux")
def test_runpath_api(tmp_path: Path):
    binadd_c = tmp_path / "binadd.c"
    libadd_c = tmp_path / "libadd.c"

    binadd_bin = tmp_path / "binadd.bin"
    libadd_so  = tmp_path / "libadd.so"

    binadd_c.write_text(BINADD_C)
    libadd_c.write_text(LIBADD_C)

    compile_libadd(libadd_so, libadd_c, [])
    compile_binadd(binadd_bin, binadd_c, [])

    binadd = lief.ELF.parse(binadd_bin.as_posix())

    rpath = lief.ELF.DynamicEntryRunPath()
    rpath = binadd.add(rpath)
    rpath += "/tmp"

    assert rpath.paths == ["/tmp"]
    assert rpath.runpath == "/tmp"

    rpath.insert(0, "/foo")

    assert rpath.paths == ["/foo", "/tmp"]
    assert rpath.runpath == "/foo:/tmp"

    rpath.paths = ["/foo", "/tmp", "/bar"]

    assert rpath.paths == ["/foo", "/tmp", "/bar"]
    assert rpath.runpath == "/foo:/tmp:/bar"

    rpath -= "/tmp"
    assert rpath.runpath == "/foo:/bar"

    rpath.remove("/foo").remove("/bar")
    assert rpath.runpath == ""

@pytest.mark.skipif(not is_linux(), reason="requires Linux")
def test_change_libname(tmp_path: Path):
    binadd_c = tmp_path / "binadd.c"
    libadd_c = tmp_path / "libadd.c"

    binadd_bin = tmp_path / "binadd.bin"
    libadd_so  = tmp_path / "libadd.so"

    binadd_c.write_text(BINADD_C)
    libadd_c.write_text(LIBADD_C)

    compile_libadd(libadd_so, libadd_c, [])
    compile_binadd(binadd_bin, binadd_c, [])

    libadd = lief.ELF.parse(libadd_so.as_posix())
    binadd = lief.ELF.parse(binadd_bin.as_posix())

    new_name = "libwhichhasalongverylongname.so"

    assert lief.ELF.DynamicEntry.TAG.SONAME in libadd
    soname_entry: lief.ELF.DynamicEntryLibrary = libadd[lief.ELF.DynamicEntry.TAG.SONAME]
    soname_entry.name = new_name

    libfoo_path = tmp_path / new_name
    libadd.write(libfoo_path.as_posix())

    libfoo = lief.ELF.parse(libfoo_path.as_posix())

    new_so_name = libfoo[lief.ELF.DynamicEntry.TAG.SONAME]
    assert isinstance(new_so_name, lief.ELF.DynamicSharedObject)
    # Check builder did the job right
    assert new_so_name.name == new_name

    libadd_needed = binadd.get_library("libadd.so")
    libadd_needed.name = new_name

    # Add a RPATH entry
    rpath = lief.ELF.DynamicEntryRunPath(tmp_path.as_posix())
    rpath = binadd.add(rpath)

    new_binadd_path = tmp_path / "binadd_updated.bin"
    binadd.write(new_binadd_path.as_posix())

    # Run the new executable
    st = os.stat(libfoo_path)
    os.chmod(libfoo_path, st.st_mode | stat.S_IEXEC)

    st = os.stat(new_binadd_path)
    os.chmod(new_binadd_path, st.st_mode | stat.S_IEXEC)

    with Popen([new_binadd_path, '1', '2'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
        stdout = P.stdout.read().decode("utf8")
        P.communicate()
        print(stdout)
        assert P.returncode == 0
        assert "From myLIb, a + b = 3" in stdout
