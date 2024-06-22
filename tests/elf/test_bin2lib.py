import os
import shlex
import stat
import subprocess
import pytest
from pathlib import Path

import lief
from utils import get_compiler, is_linux, is_x86_64, is_aarch64

if not is_linux():
    pytest.skip("requires Linux", allow_module_level=True)

lief.logging.set_level(lief.logging.LEVEL.INFO)

class CommandResult:
    def __init__(self, output, error, retcode, process=None):
        self.output = output
        self.error = error
        self.retcode = retcode
        self.process = process

    def __bool__(self):
        return not self.retcode

    def __str__(self):
        if bool(self):
            return self.output
        return self.error


LIBADD_C = """\
#include <stdlib.h>
#include <stdio.h>
#define LOCAL __attribute__ ((visibility ("hidden")))

LOCAL int add_hidden(int a, int b) {
  printf("[LOCAL] %d + %d = %d\\n", a, b, a+b);
  return a + b;
}


int main(int argc, char** argv) {

  if (argc != 3) {
    printf("Usage: %s <a> <b>\\n", argv[0]);
    exit(-1);
  }

  printf("Hello\\n");
  int res = add_hidden(atoi(argv[1]), atoi(argv[2]));
  printf("From add_hidden@libadd.so a + b = %d\\n", res);
  return 0;
}
"""


BINADD_C = """\
#include <stdio.h>
#include <stdlib.h>
extern int add_hidden(int a, int b);

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <a> <b>\\n", argv[0]);
    exit(-1);
  }

  printf("Hello\\n");
  int res = add_hidden(atoi(argv[1]), atoi(argv[2]));
  printf("From add_hidden@libadd.so a + b = %d\\n", res);
  return 0;
}
"""


def run_cmd(cmd):
    print(f"Running: '{cmd}'")
    cmd = shlex.split(cmd)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()

    if stdout:
        print(stdout)

    if stderr:
        print(stderr)

    return CommandResult(stdout, stderr, p.returncode)

def modif_1(libadd: lief.ELF.Binary, output: Path):
    libadd_hidden: lief.ELF.Symbol = libadd.get_symbol("add_hidden")
    libadd_hidden.binding    = lief.ELF.Symbol.BINDING.GLOBAL
    libadd_hidden.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
    libadd_hidden            = libadd.add_dynamic_symbol(libadd_hidden, lief.ELF.SymbolVersion.global_) # type: ignore

    if lief.ELF.DynamicEntry.TAG.FLAGS_1 in libadd:
        flags_1: lief.ELF.DynamicEntryFlags = libadd[lief.ELF.DynamicEntry.TAG.FLAGS_1]
        if flags_1.has(lief.ELF.DynamicEntryFlags.FLAG.PIE):
            flags_1.remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)

    print(libadd_hidden)

    libadd.add(lief.ELF.DynamicSharedObject(output.name))
    libadd.write(output.as_posix())

def modif_2(libadd: lief.ELF.Binary, output: Path):
    libadd.export_symbol("add_hidden")

    if lief.ELF.DynamicEntry.TAG.FLAGS_1 in libadd:
        flags_1: lief.ELF.DynamicEntryFlags = libadd[lief.ELF.DynamicEntry.TAG.FLAGS_1]
        if flags_1.has(lief.ELF.DynamicEntryFlags.FLAG.PIE):
            flags_1.remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)

    libadd.write(output.as_posix())

def modif_3(libadd: lief.ELF.Binary, output: Path):
    add_hidden_static = libadd.get_symtab_symbol("add_hidden")
    assert isinstance(add_hidden_static.name, str)
    libadd.add_exported_function(add_hidden_static.value, add_hidden_static.name)

    if lief.ELF.DynamicEntry.TAG.FLAGS_1 in libadd:
        flags_1: lief.ELF.DynamicEntryFlags = libadd[lief.ELF.DynamicEntry.TAG.FLAGS_1]
        if flags_1.has(lief.ELF.DynamicEntryFlags.FLAG.PIE):
            flags_1.remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)

    libadd.write(output.as_posix())


@pytest.mark.parametrize("modifier", [
    modif_1, modif_2, modif_3
])
def test_libadd(tmp_path: Path, modifier):
    if not is_linux():
        pytest.skip("unsupported system")

    libadd_src = tmp_path / "libadd.c"
    binadd_src = tmp_path / "binadd.c"

    libadd_src.write_text(LIBADD_C)
    binadd_src.write_text(BINADD_C)


    binadd_bin = tmp_path / "binadd.bin"
    libadd_so  = tmp_path / "libadd.so"
    libadd2_so = tmp_path / "libadd2.so"

    compiler = get_compiler()

    fmt = ""
    if is_x86_64():
        fmt = "{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -o {output} {input}"

    if is_aarch64():
        fmt = "{compiler} -Wl,--export-dynamic -fPIE -pie -o {output} {input}"

    # Compile libadd
    r = run_cmd(fmt.format(compiler=compiler,
                           output=libadd_so, input=libadd_src))
    assert r

    libadd = lief.ELF.parse(libadd_so.as_posix())
    modifier(libadd, libadd2_so)

    lib_directory = libadd2_so.parent
    libname = libadd2_so.stem[3:] # libadd.so ---> add

    fmt = ""
    if is_x86_64():
        fmt = "{compiler} -Wl,--export-dynamic -mcmodel=large -fPIE -pie -Wl,-rpath={libdir} -L{libdir} -o {output} {input} -l{libadd2}"

    if is_aarch64():
        fmt = "{compiler} -Wl,--export-dynamic -fPIE -pie -Wl,-rpath={libdir} -L{libdir} -o {output} {input} -l{libadd2}"

    r = run_cmd(fmt.format(compiler=compiler,
                           libdir=lib_directory, libadd2=libname,
                           output=binadd_bin, input=binadd_src))

    assert r

    st = os.stat(binadd_bin)
    os.chmod(binadd_bin, st.st_mode | stat.S_IEXEC)

    r = run_cmd(f"{binadd_bin} 1 2")
    assert r
    assert "From add_hidden@libadd.so a + b = 3" in r.output
