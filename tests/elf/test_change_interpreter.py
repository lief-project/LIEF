import os
import signal
import stat
import subprocess
from pathlib import Path
from subprocess import Popen

import lief
import pytest
from utils import check_layout


@pytest.mark.linux
@pytest.mark.parametrize(
    "target",
    [
        "/bin/ls",
        "/usr/bin/ls",
        "/usr/bin/ssh",
        "/usr/bin/nm",
        "/usr/bin/cp",
        "/usr/bin/find",
        "/usr/bin/file",
    ],
)
def test_change_interpreter(tmp_path: Path, target):
    target = Path(target)
    if not target.is_file():
        return

    name = target.name
    target = lief.ELF.parse(target)
    assert target is not None
    new_interpreter = tmp_path / Path(target.interpreter).name
    if not new_interpreter.is_symlink():
        os.symlink(target.interpreter, new_interpreter)
    target.interpreter = new_interpreter.as_posix()
    output = tmp_path / f"{name}.interpreter"
    target.write(output)

    check_layout(output)

    st = os.stat(output)
    os.chmod(output, st.st_mode | stat.S_IEXEC)

    with Popen(
        output.as_posix(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as P:
        assert P.stdout is not None
        stdout = P.stdout.read().decode("utf8")
        lief.logging.info(stdout)
        P.communicate()
        assert P.returncode != -signal.SIGSEGV
