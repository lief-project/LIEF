#!/usr/bin/env python
'''
This script disassembles an ELF/PE/Mach-O binary using LIEF's extended API

Note: this script is only working with the extended version of LIEF
'''
import argparse
import lief

from pathlib import Path

def disassemble(target: lief.Binary, addr: int):
    for inst in target.disassemble(addr):
        print(inst)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help='Target file', type=Path)
    parser.add_argument("address", help='Address to disassemble',
                        type=lambda x: int(x,0))

    args = parser.parse_args()

    target_file = args.file
    addr = args.address

    target = lief.parse(target_file)
    if target is None:
        print(f"Can't load: {target_file}")
        return 1

    disassemble(target, addr)

if __name__ == "__main__":
    raise SystemExit(main())
