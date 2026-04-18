import sys
from pathlib import Path

import pytest
from pytest import MonkeyPatch
from utils import import_from_file, lief_samples_dir

samples_dir = Path(lief_samples_dir())

LIEF_PY_DIR = Path(__file__).parent / ".." / ".." / "api" / "python" / "examples"


@pytest.mark.parametrize(
    "pe",
    [
        "PE/PE32_x86_library_kernel32.dll",
        "PE/PE64_x86-64_atapi.sys",
    ],
)
def test_pe_reader(monkeypatch: MonkeyPatch, pe: str) -> None:
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "pe_reader.py"
    pe_reader = import_from_file("pe_reader", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, "--all", sample.as_posix()])
        pe_reader.main()


@pytest.mark.parametrize(
    "pe",
    [
        "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe",
    ],
)
def test_pe_authenticode_reader(
    monkeypatch: MonkeyPatch, tmp_path: Path, pe: str
) -> None:
    out = tmp_path / "out.p7b"
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "authenticode" / "authenticode_reader.py"
    authenticode_reader = import_from_file("authenticode_reader", target)

    with monkeypatch.context() as m:
        m.setattr(
            sys,
            "argv",
            [
                target.name,
                "--all",
                "--crt",
                "--hash",
                "--check",
                "--allow-expired",
                "--save",
                out.as_posix(),
                sample.as_posix(),
            ],
        )
        authenticode_reader.main()


@pytest.mark.parametrize(
    "pe",
    [
        "PE/PE32_x86-64_binary_avast-free-antivirus-setup-online.exe",
    ],
)
def test_pe_authenticode_api(monkeypatch: MonkeyPatch, pe: str) -> None:
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "authenticode" / "api_example.py"

    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        import_from_file("api_example", target)


@pytest.mark.parametrize(
    "pe",
    [
        "PE/PE32_x86_library_kernel32.dll",
    ],
)
def test_pe_json(monkeypatch: MonkeyPatch, pe: str) -> None:
    sample = samples_dir / Path(pe)
    target = LIEF_PY_DIR / "pe_json.py"
    module = import_from_file("pe_json", target)
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        module.main()


def test_pe_resources_manager(monkeypatch: MonkeyPatch) -> None:
    sample = samples_dir / "PE" / "CloudNotifications.exe"
    target = LIEF_PY_DIR / "pe_resources_manager.py"
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        import_from_file("pe_resources_manager", target)


def test_pe_forwardinfo(monkeypatch: MonkeyPatch) -> None:
    sample = samples_dir / "PE" / "PE32_x86_library_kernel32.dll"
    target = LIEF_PY_DIR / "pe_forwardinfo.py"
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        import_from_file("pe_forwardinfo", target)


def test_pe_authenticode(monkeypatch: MonkeyPatch) -> None:
    sample = (
        samples_dir / "PE" / "PE32_x86-64_binary_avast-free-antivirus-setup-online.exe"
    )
    target = LIEF_PY_DIR / "pe_authenticode.py"
    with monkeypatch.context() as m:
        m.setattr(sys, "argv", [target.name, sample.as_posix()])
        import_from_file("pe_authenticode", target)
