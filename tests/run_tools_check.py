import pytest
import os
import argparse
from pathlib import Path

CWD = Path(__file__).parent

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build_dir")

    args = parser.parse_args()

    os.environ.setdefault("LIEF_BUILD_DIR", args.build_dir)
    pytest.main([
        CWD / "elf" / "check_bin_examples.py",
        CWD / "elf" / "check_python_examples.py",

        CWD / "macho" / "check_bin_examples.py",
        CWD / "macho" / "check_python_examples.py",

        CWD / "pe" / "check_bin_examples.py",
        CWD / "pe" / "check_python_examples.py",

        "--verbose"
    ])

if __name__ == "__main__":
    main()
