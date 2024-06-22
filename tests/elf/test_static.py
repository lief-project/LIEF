#!/usr/bin/env python
import subprocess
from pathlib import Path
from subprocess import Popen
import pytest

import lief
from utils import get_compiler, is_linux

if not is_linux():
    pytest.skip("requires Linux", allow_module_level=True)

COMPILER = get_compiler()

lief.logging.set_level(lief.logging.LEVEL.INFO)

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

ADD_C = """\
int add(int a, int b) {
    return a + b;
}
"""

def compile_obj(out: Path, infile: Path):
    cmd = [COMPILER, '-c', '-o', out, infile]
    print("Compile 'binadd' with: {}".format(" ".join(map(str, cmd))))

    with Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=out.parent) as P:
        stdout = P.stdout.read().decode('utf8')
        print(stdout)

def compile_bin(out: Path, obj: Path, add_c: Path):
    cmd = [COMPILER, '-o', out, obj, add_c]
    print("Compile 'binadd' with: {}".format(" ".join(map(str, cmd))))
    with Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=out.parent) as P:
        stdout = P.stdout.read().decode('utf8')
        print(stdout)


@pytest.mark.skipif(not is_linux(), reason="requires Linux")
def test_write_object(tmp_path: Path):
    binadd_c   = tmp_path / "binadd.c"
    add_c      = tmp_path / "add.c"
    binadd_o   = tmp_path / "binadd.o"
    newfile_o  = tmp_path / "newfile.o"
    binadd_bin = tmp_path / "binadd.bin"

    binadd_c.write_text(BINADD_C)
    add_c.write_text(ADD_C)

    compile_obj(binadd_o, binadd_c)

    binadd = lief.ELF.parse(binadd_o.as_posix())
    init_obj = [str(o).strip() for o in binadd.object_relocations]

    binadd.write(newfile_o.as_posix())
    binadd = lief.ELF.parse(newfile_o.as_posix())
    new_obj = [str(o).strip() for o in binadd.object_relocations]

    assert len(init_obj) == len(new_obj)

    for new, old in zip(new_obj, init_obj):
        assert new == old

    # Check it can still be compiled
    compile_bin(binadd_bin, newfile_o, add_c)
    assert subprocess.check_output([binadd_bin, "2", "3"]).decode('ascii', 'ignore') == \
           'From myLIb, a + b = 5\n'

@pytest.mark.skipif(not is_linux(), reason="requires Linux")
def test_update_addend_object(tmp_path: Path):
    binadd_c   = tmp_path / "binadd.c"
    binadd_o   = tmp_path / "binadd.o"
    newfile_o  = tmp_path / "newfile.o"

    binadd_c.write_text(BINADD_C)

    compile_obj(binadd_o, binadd_c)
    binadd = lief.ELF.parse(binadd_o.as_posix())
    reloc = next(o for o in binadd.object_relocations if o.symbol.name == "add")

    reloc.addend = 0xABCD
    binadd.write(newfile_o.as_posix())
    binadd = lief.ELF.parse(newfile_o.as_posix())
    reloc = next(o for o in binadd.object_relocations if o.symbol.name == "add")

    assert reloc.addend == 0xABCD
