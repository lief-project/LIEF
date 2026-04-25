#!/usr/bin/env python
"""Strip the section table from an ELF binary.

Zeros out the ``e_shoff`` and ``e_shnum`` fields of the ELF header so
that tools relying on the section table (notably ``gdb``, ``readelf
-S``) lose visibility into the binary while the program headers
remain intact and the file still runs.

Example:

    $ python elf_remove_section_table.py /bin/ls ls_nosec
    $ readelf -S ls_nosec
    There are no sections in this file.
    $ ./ls_nosec      # still runs
"""

import argparse
import sys

import lief


def remove_section_table(filename: str, output: str) -> int:
    binary = lief.ELF.parse(filename)
    if binary is None:
        print(f"Error: failed to parse '{filename}' as ELF", file=sys.stderr)
        return 1

    header = binary.header
    header.section_header_offset = 0
    header.numberof_sections = 0
    binary.write(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("input", metavar="<elf>", help="Input ELF binary")
    parser.add_argument("output", metavar="<out>", help="Path to the rewritten binary")
    args = parser.parse_args()
    return remove_section_table(args.input, args.output)


if __name__ == "__main__":
    sys.exit(main())
