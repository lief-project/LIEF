#!/usr/bin/env python
import os
import signal
import stat
import subprocess
import pytest
from pathlib import Path
from subprocess import Popen

import lief
from utils import is_linux

lief.logging.set_level(lief.logging.LEVEL.INFO)

@pytest.mark.skipif(not is_linux(), reason="requires Linux")
@pytest.mark.parametrize("target", [
    '/bin/ls',      '/usr/bin/ls',
    '/usr/bin/ssh', '/usr/bin/nm',
    '/usr/bin/cp',  '/usr/bin/find',
    '/usr/bin/file',
])
def test_change_interpreter(tmp_path: Path, target):
    target = Path(target)
    if not target.is_file():
        return

    name = target.name
    target = lief.parse(target.as_posix())
    new_interpreter = tmp_path / Path(target.interpreter).name
    if not new_interpreter.is_symlink():
        os.symlink(target.interpreter, new_interpreter)
    target.interpreter = new_interpreter.as_posix()
    output = tmp_path / f"{name}.interpreter"
    target.write(output.as_posix())

    if is_linux():
        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        with Popen(output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as P:
            stdout = P.stdout.read().decode("utf8")
            print(stdout)
            P.communicate()
            assert P.returncode != -signal.SIGSEGV
