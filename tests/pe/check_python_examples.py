import pytest
import sys
from pathlib import Path
from subprocess import check_call

from utils import lief_samples_dir

samples_dir = Path(lief_samples_dir())

LIEF_PY_DIR = Path(__file__).parent / ".." / ".." / "api" / "python" / "examples"

@pytest.mark.parametrize("pe", [
    "PE/PE32_x86_library_kernel32.dll",
    "PE/PE64_x86-64_atapi.sys",
])
def test_pe_reader(pe):
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "pe_reader.py"
    check_call([sys.executable, target, "--all", sample])

@pytest.mark.parametrize("pe", [
    "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe",
])
def test_pe_authenticode_reader(tmp_path: Path, pe):
    out = tmp_path / "out.p7b"
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "authenticode" / "authenticode_reader.py"
    check_call([sys.executable, target,
        "--all", "--crt", "--hash", "--check", "--allow-expired", "--save",
        out, sample])

@pytest.mark.parametrize("pe", [
    "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe",
])
def test_pe_authenticode_api(pe):
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "authenticode" / "api_example.py"
    check_call([sys.executable, target, sample])
