import argparse
import os
import sys
from pathlib import Path

import pytest

CWD = Path(__file__).parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build_dir")

    args = parser.parse_args()

    os.environ.setdefault("LIEF_BUILD_DIR", args.build_dir)
    retcode = pytest.main(
        [
            str(e)
            for e in [
                CWD / "elf/check_bin_examples.py",
                CWD / "elf/check_python_examples.py",
                CWD / "macho/check_bin_examples.py",
                CWD / "macho/check_python_examples.py",
                CWD / "pe/check_bin_examples.py",
                CWD / "pe/check_python_examples.py",
                "--verbose",
            ]
        ]
    )

    print(f"Retcode: {retcode}")
    sys.exit(retcode)


if __name__ == "__main__":
    main()
