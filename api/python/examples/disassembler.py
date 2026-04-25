#!/usr/bin/env python
"""Disassemble instructions at an address of an ELF/PE/Mach-O binary.

Uses LIEF's extended disassembly API to iterate over the instructions
located at the given virtual address of the binary.

Note: only available with the extended version of LIEF.

Example:

    $ python disassembler.py /bin/ls 0x4000
"""

import argparse
import sys
from pathlib import Path

import lief


def disassemble(target: lief.Binary, addr: int) -> None:
    for inst in target.disassemble(addr):
        print(inst)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="Target binary", type=Path)
    parser.add_argument(
        "address", help="Address to disassemble", type=lambda x: int(x, 0)
    )
    args = parser.parse_args()

    target = lief.parse(args.file)
    if target is None:
        print(f"Can't load: {args.file}", file=sys.stderr)
        return 1
    if isinstance(target, lief.COFF.Binary):
        print("COFF binaries are not supported by the disassembler", file=sys.stderr)
        return 1

    disassemble(target, args.address)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
