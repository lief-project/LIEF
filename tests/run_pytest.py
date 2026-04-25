import argparse
import sys
from pathlib import Path
from typing import Optional

import pytest

CWD = Path(__file__).parent


def run(
    junit_xml: Optional[str] = None,
    skip_slow: bool = False,
    parallel_threads: int | None = None,
):
    args = [
        str(e)
        for e in [
            CWD / "macho",
            CWD / "pe",
            CWD / "elf",
            CWD / "oat",
            CWD / "vdex",
            CWD / "dex",
            CWD / "art",
            CWD / "api",
            CWD / "pdb",
            CWD / "dwarf",
            CWD / "objc",
            CWD / "dyld-shared-cache",
            CWD / "assembly",
            CWD / "abstract",
            CWD / "coff",
            "--verbose",
        ]
    ]
    if junit_xml is not None:
        args.append(f"--junit-xml={junit_xml}")

    if skip_slow:
        args.append("--skip-slow")

    if parallel_threads is not None:
        args.append(f"--parallel-threads={parallel_threads}")

    retcode = pytest.main(args)

    print(f"Retcode: {retcode}")
    sys.exit(retcode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--junit-xml", metavar="JUNIT_XML", dest="junit_xml", default=None, type=str
    )

    parser.add_argument("--parallel-threads", default=None, type=int)

    parser.add_argument(
        "--skip-slow",
        action="store_true",
        dest="skip_slow",
        help="Skip slow tests",
    )
    args = parser.parse_args()
    run(args.junit_xml, args.skip_slow, args.parallel_threads)


if __name__ == "__main__":
    main()
