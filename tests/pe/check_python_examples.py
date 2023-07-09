import pytest
import sys
from pathlib import Path

from utils import lief_samples_dir, import_from_file

samples_dir = Path(lief_samples_dir())

LIEF_PY_DIR = Path(__file__).parent / ".." / ".." / "api" / "python" / "examples"

@pytest.mark.parametrize("pe", [
    "PE/PE32_x86_library_kernel32.dll",
    "PE/PE64_x86-64_atapi.sys",
])
def test_pe_reader(monkeypatch, pe):
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "pe_reader.py"
    pe_reader = import_from_file("pe_reader", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, "--all", sample.as_posix()])
        pe_reader.main()

@pytest.mark.parametrize("pe", [
    "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe",
])
def test_pe_authenticode_reader(monkeypatch, tmp_path: Path, pe):
    out = tmp_path / "out.p7b"
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "authenticode" / "authenticode_reader.py"
    authenticode_reader = import_from_file("authenticode_reader", target)

    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name,
            "--all", "--crt", "--hash", "--check", "--allow-expired", "--save",
            out.as_posix(), sample.as_posix()])
        authenticode_reader.main()

@pytest.mark.parametrize("pe", [
    "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe",
])
def test_pe_authenticode_api(monkeypatch, pe):
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "authenticode" / "api_example.py"

    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        api_example = import_from_file("api_example", target)
