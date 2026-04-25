#!/usr/bin/env python
"""Create a companion DWARF file from a PE binary.

Demonstrates the DWARF editor API: loads a PE binary, synthesises a
compilation unit with one function returning a pointer to a
structure and a stack variable, then writes the result to
``/tmp/out.debug``.

Note: only available with the extended version of LIEF.

Example:

    $ python dwarf_editor.py program.exe
"""

import argparse
import sys

import lief


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("file", help="Input PE binary")
    parser.add_argument(
        "--output",
        default="/tmp/out.debug",
        help="Output DWARF file (default: %(default)s)",
    )
    args = parser.parse_args()

    if not lief.__extended__:
        print("This example requires the extended version of LIEF", file=sys.stderr)
        return 1

    pe = lief.PE.parse(args.file)
    if pe is None:
        print(f"Error: failed to parse '{args.file}' as PE", file=sys.stderr)
        return 1

    editor = lief.dwarf.Editor.from_binary(pe)
    if editor is None:
        print("Failed to create a DWARF editor", file=sys.stderr)
        return 1

    unit = editor.create_compilation_unit()
    unit.set_producer("LIEF")

    func = unit.create_function("hello")
    func.set_address(0x123)

    pointer_type = unit.create_structure("my_struct_t").pointer_to()
    if pointer_type is None:
        print("Failed to create the pointer type", file=sys.stderr)
        return 1
    func.set_return_type(pointer_type)

    var = func.create_stack_variable("local_var")
    var.set_stack_offset(8)

    editor.write(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
