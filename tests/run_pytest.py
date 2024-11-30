import pytest
import sys
import time
import argparse

from typing import Optional
from pathlib import Path

CWD = Path(__file__).parent

def run(junit_xml: Optional[str] = None):
    args = [
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
    ]
    if junit_xml is not None:
        args.append(f"--junit-xml={junit_xml}")

    retcode = pytest.main(args)

    print(f"Retcode: {retcode}")
    sys.exit(retcode)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--junit-xml",
        metavar="JUNIT_XML",
        dest="junit_xml",
        default=None,
        type=str
    )
    args = parser.parse_args()
    run(args.junit_xml)

if __name__ == "__main__":
    main()
