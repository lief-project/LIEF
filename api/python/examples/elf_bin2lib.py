#!/usr/bin/env python
"""Promote a PIE executable to a shared library by exporting a function.

Takes a PIE ELF executable, declares an exported function at the
given address, and rewrites the binary so that it can be ``dlopen``-ed
and the function invoked via ``dlsym``.

Example:

    $ python elf_bin2lib.py -n compute -o libcompute.so ./prog 0x1200
"""

import argparse
import sys

import lief


def bin2lib(binary: lief.ELF.Binary, address: int, output: str, name: str = "") -> int:
    if not binary.is_pie:
        print("It only works with PIE binaries", file=sys.stderr)
        return 1

    function = binary.add_exported_function(address, name)
    print("Function created:", function)
    binary.write(output)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--name", "-n", default="", help="Name of the function to create"
    )
    parser.add_argument(
        "--output", "-o", default="libfoo.so", help="Output name (default: %(default)s)"
    )
    parser.add_argument("binary", help="The target ELF binary")
    parser.add_argument(
        "address", type=lambda e: int(e, 0), help="Address of the function to export"
    )

    args = parser.parse_args()
    binary = lief.ELF.parse(args.binary)
    if binary is None:
        print(f"Error: failed to parse '{args.binary}' as ELF", file=sys.stderr)
        return 1

    return bin2lib(binary, args.address, args.output, name=args.name)


if __name__ == "__main__":
    sys.exit(main())
