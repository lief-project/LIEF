#!/usr/bin/env python
"""Inspect a Microsoft PDB (Program Database) file.

Loads a ``.pdb`` file and walks its contents: GUID/age metadata,
public symbols, user-defined types (classes) and per-compilation-unit
information (source files and functions).

Note: only available with the extended version of LIEF.

Example:

    $ python pdb_inspect.py ./program.pdb
"""

import argparse
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="Path to the PDB file")
    args = parser.parse_args()

    pdb = lief.pdb.load(args.file)
    if pdb is None:
        print(f"Error: failed to load '{args.file}'", file=sys.stderr)
        return 1

    print(f"age={pdb.age}, guid={pdb.guid}")

    for sym in pdb.public_symbols:
        print(f"name={sym.name}, section={sym.section_name}, RVA={sym.RVA}")

    for ty in pdb.types:
        if isinstance(ty, lief.pdb.types.Class):
            print(f"Class[name]={ty.name}")

    for cu in pdb.compilation_units:
        print(f"module={cu.module_name}")
        for src in cu.sources:
            print(f"  - {src}")
        for func in cu.functions:
            print(
                f"name={func.name}, section={func.section_name}, "
                f"RVA={func.RVA}, code_size={func.code_size}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
