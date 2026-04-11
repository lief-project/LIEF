import os
import re
import stat
import subprocess
from pathlib import Path
from subprocess import Popen

import lief
from utils import check_layout, get_sample, has_recent_glibc, is_linux, is_x86_64

is_updated_linux = is_linux() and is_x86_64() and has_recent_glibc()


def test_simple(tmp_path: Path):
    sample_path = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    output = tmp_path / "ls.section"

    ls = lief.ELF.parse(sample_path)
    assert ls is not None
    ls.remove_section(".text", clear=False)
    ls.write(output)
    check_layout(ls)

    if is_updated_linux:
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(
            [output, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as P:
            assert P.stdout is not None
            stdout = P.stdout.read().decode("utf8")
            lief.logging.info(stdout)
            assert re.search(r"GNU coreutils", stdout) is not None
