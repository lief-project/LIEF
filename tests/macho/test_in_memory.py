import lief
import pytest
from shutil import which
from pathlib import Path
from utils import is_osx
import subprocess
from subprocess import Popen
import ctypes


pytest.skip("not supported yet", allow_module_level=True)
#if not is_osx():
#    pytest.skip("requires OSX", allow_module_level=True)

LIB_TEST = r"""\
#include <stdio.h>
#include <stdlib.h>
#include <string>

#define API_EXPORT __attribute__((visibility("default")))

static int counter = 0;
static std::string MSG;

extern "C" {
API_EXPORT int do_add(int x) {
  MSG = std::to_string(x);
  printf("Counter is %d (%s)\n", counter, MSG.c_str());
  counter++;
  return counter + x;
}
}
"""

def get_address(func):
    return ctypes.cast(func, ctypes.c_void_p).value

def compile(src: Path, dst: Path, extra_flags = None):
    COMPILER = which("clang++")
    assert COMPILER is not None

    CC_FLAGS = ['-fPIC', '-shared']
    if extra_flags is not None:
        if isinstance(extra_flags, str):
            CC_FLAGS += [extra_flags]
        elif isinstance(extra_flags, list):
            CC_FLAGS += extra_flags

    cmd = [COMPILER] + CC_FLAGS + ['-o', dst.as_posix(), src.as_posix()]

    with Popen(cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
        output = proc.stdout.read()
        print(output)
        return output

    return None

def close(handler):
    ctypes.cdll.LoadLibrary("libc.dylib").dlclose(handler._handle)

@pytest.mark.parametrize("version", [
    '-mmacosx-version-min=10.9', # To test without the chained fixups
    ''
])
def test_parse_in_memory(tmp_path: Path, version):
    libadd_src = tmp_path / "libadd.cpp"
    libadd_src.write_text(LIB_TEST)

    libadd_so = tmp_path / "libadd.so"
    compile(libadd_src, libadd_so, version)

    libadd = lief.parse(libadd_so.as_posix())
    lib = ctypes.cdll.LoadLibrary(libadd_so.as_posix())
    base_address = get_address(lib.do_add) - libadd.get_symbol("_do_add").value
    assert base_address > 0

    config = lief.MachO.ParserConfig()
    config.parse_dyld_exports  = True
    config.parse_dyld_bindings = True
    config.parse_dyld_rebases  = True
    config.fix_from_memory     = True

    libadd_mem = lief.MachO.parse_from_memory(base_address, config)

    # Write the library loaded in memory
    libadd_mem_so = tmp_path / "libadd_mem.so"
    libadd_mem.write(libadd_mem_so.as_posix())

    # Load the written library
    lib_mem = ctypes.cdll.LoadLibrary(libadd_mem_so.as_posix())

    assert lib.do_add(1) == 2
    assert lib_mem.do_add(1) == 2

    close(lib)
    close(lib_mem)
