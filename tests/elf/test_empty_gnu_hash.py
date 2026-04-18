import ctypes
import os
import stat
from pathlib import Path
from typing import cast

import lief
from utils import check_layout, get_sample, glibc_version, is_linux, is_x86_64


def test_gnu_hash(tmpdir: Path):
    target_path = get_sample("ELF/ELF64_x86-64_binary_empty-gnu-hash.bin")
    output = os.path.join(tmpdir, "libnoempty.so")

    binary = lief.ELF.parse(target_path)
    assert binary is not None
    entry_flag = cast(
        lief.ELF.DynamicEntryFlags, binary[lief.ELF.DynamicEntry.TAG.FLAGS_1]
    )
    entry_flag.remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)

    symbols = {
        "myinstance": 0x1159,
        "myinit": 0x1175,
        "mycalc": 0x1199,
        "mydelete": 0x1214,
    }

    for name, addr in symbols.items():
        binary.add_exported_function(addr, name)
    binary.write(output)

    check_layout(output)

    if is_linux() and is_x86_64() and glibc_version() >= (2, 30):
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)
        lief.logging.info(output)

        lib = ctypes.cdll.LoadLibrary(output)

        # Raise 'AttributeError' if not exported
        lief.logging.info(lib.myinstance)
        assert lib.myinstance is not None
