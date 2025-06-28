import lief
import os
import subprocess
import pytest
from subprocess import Popen
from utils import get_sample, has_private_samples, is_linux, is_x86_64
from pathlib import Path

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_parser_builder(tmp_path: Path):
    libc = lief.ELF.parse(get_sample("private/ELF/x32/libc.so.6"))

    assert libc.dynamic_entries[12].tag == lief.ELF.DynamicEntry.TAG.X86_64_PLTENT
    assert libc.dynamic_entries[12].value == 0x10

    output = tmp_path / "libc.so.6"

    libc.relocate_phdr_table()
    config = lief.ELF.Builder.config_t()
    config.force_relocate = True
    libc.write(output.as_posix(), config)

    if is_linux() and is_x86_64():
        ld = get_sample("private/ELF/x32/ld-linux-x32.so.2")
        env = os.environ
        with Popen([ld, output.as_posix()], universal_newlines=True, env=env,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
            stdout = proc.stdout.read()
            proc.poll()
            assert "Compiled by GNU CC version 14.2.0." in stdout
