import re
import stat
import subprocess
from pathlib import Path
from subprocess import Popen
from typing import cast

import lief
import pytest
from utils import check_layout, get_sample, has_recent_glibc, is_linux, is_x86_64


@pytest.mark.linux
def test_freebl(tmp_path: Path):
    libfreebl3_path = get_sample("ELF/ELF64_x86-64_library_libfreebl3.so")

    output_ls = tmp_path / "ls.new"
    output_libfreebl3 = tmp_path / "libfreebl3.so"

    libfreebl3 = lief.ELF.parse(libfreebl3_path)
    assert libfreebl3 is not None
    ls = lief.ELF.parse("/usr/bin/ls")
    if ls is None:  # pragma: no cover
        ls = lief.ELF.parse("/bin/ls")
    assert ls is not None

    if lief.ELF.DynamicEntry.TAG.FLAGS_1 in ls:
        flags_1 = cast(
            lief.ELF.DynamicEntryFlags, ls[lief.ELF.DynamicEntry.TAG.FLAGS_1]
        )
        if flags_1.has(lief.ELF.DynamicEntryFlags.FLAG.PIE):
            flags_1.remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)

    ls.add_library("libfreebl3.so")

    ls += lief.ELF.DynamicEntryRunPath("$ORIGIN")
    libfreebl3 += lief.ELF.DynamicEntryRunPath("$ORIGIN")

    ls.write(output_ls)
    libfreebl3.write(output_libfreebl3)

    check_layout(output_ls)
    check_layout(output_libfreebl3)

    if is_linux() and is_x86_64() and has_recent_glibc():
        output_ls.chmod(output_ls.stat().st_mode | stat.S_IEXEC)
        output_libfreebl3.chmod(output_libfreebl3.stat().st_mode | stat.S_IEXEC)
        with Popen(
            [output_ls, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            lief.logging.info(stdout.decode("utf8"))
            assert (
                re.search(r"ls \(GNU coreutils\) ", stdout.decode("utf8")) is not None
            )
