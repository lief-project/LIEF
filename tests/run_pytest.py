import pytest
import sys
from pathlib import Path

CWD = Path(__file__).parent

if __name__ == "__main__":
    retcode = pytest.main([
        (CWD / "macho"),
        (CWD / "pe"),
        (CWD / "elf"),
        (CWD / "oat"),
        (CWD / "vdex"),
        (CWD / "dex"),
        (CWD / "art"),
        (CWD / "api"),
        (CWD / "pdb"),
        (CWD / "dwarf"),
        (CWD / "objc"),
        (CWD / "dyld-shared-cache"),
        (CWD / "assembly"),
        (CWD / "abstract"),
        "--verbose"
    ])
    print(f"Retcode: {retcode}")
    sys.exit(retcode)
