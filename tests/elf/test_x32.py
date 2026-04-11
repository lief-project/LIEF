import os
import subprocess
from pathlib import Path
from subprocess import Popen

import lief
import pytest
from utils import check_layout, get_sample, is_linux, is_x86_64, parse_elf


@pytest.mark.private
def test_parser_builder(tmp_path: Path):
    libc = parse_elf("private/ELF/x32/libc.so.6")

    assert libc.dynamic_entries[12].tag == lief.ELF.DynamicEntry.TAG.X86_64_PLTENT
    assert libc.dynamic_entries[12].value == 0x10

    output = tmp_path / "libc.so.6"

    libc.relocate_phdr_table()
    config = lief.ELF.Builder.config_t()
    config.force_relocate = True
    libc.write(output, config)

    check_layout(output)

    if is_linux() and is_x86_64():
        ld = get_sample("private/ELF/x32/ld-linux-x32.so.2")
        env = os.environ
        with Popen(
            [ld, output.as_posix()],
            universal_newlines=True,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as proc:
            assert proc.stdout is not None
            stdout = proc.stdout.read()
            proc.poll()
            assert "Compiled by GNU CC version 14.2.0." in stdout
