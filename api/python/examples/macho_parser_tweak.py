#!/usr/bin/env python
"""Benchmark Mach-O parsing with and without dyld info.

Illustrates how to tune ``lief.MachO.ParserConfig`` to skip the
(expensive) dyld bindings/exports/rebases parsing, then to re-parse
with ``full_dyldinfo`` enabled, printing the elapsed time for both
passes.

Example:

    $ python macho_parser_tweak.py /usr/bin/ls
"""

import argparse
import sys
import time

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="Path to a Mach-O binary")
    args = parser.parse_args()

    # Skip the dyld info parsing.
    config = lief.MachO.ParserConfig()
    config.parse_dyld_bindings = False
    config.parse_dyld_exports = False
    config.parse_dyld_rebases = False

    t1 = time.time()
    lief.MachO.parse(args.file, config)
    t2 = time.time()
    print(f"Without dyld info: {t2 - t1:.3f}s")

    # Parse the dyld info.
    config.full_dyldinfo(True)
    t1 = time.time()
    lief.MachO.parse(args.file, config)
    t2 = time.time()
    print(f"With dyld info:    {t2 - t1:.3f}s")

    return 0


if __name__ == "__main__":
    sys.exit(main())
