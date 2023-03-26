import pytest
from pathlib import Path

CWD = Path(__file__).parent

pytest.main([
    (CWD / "macho"),
    (CWD / "pe"),
    (CWD / "elf"),
    (CWD / "oat"),
    (CWD / "vdex"),
    (CWD / "dex"),
    (CWD / "art"),
    (CWD / "api"),
    (CWD / "abstract"),
    "--verbose"
])
