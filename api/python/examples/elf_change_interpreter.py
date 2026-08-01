#!/usr/bin/env python
"""Change the program interpreter of an ELF executable.

Replaces the ``PT_INTERP`` entry (the ``.interp`` section) of a
dynamically-linked ELF executable with the path of another ELF
interpreter, then writes the patched binary to disk with the execute
bit set.

Example:

    $ python elf_change_interpreter.py \\
        --output /tmp/ls_musl /bin/ls /usr/lib/ld-musl-x86_64.so.1
"""

import argparse
import stat
import sys
from pathlib import Path

import lief


def change_interpreter(
    target: Path, interpreter: Path, output: Path | None = None
) -> int:
    if not target.is_file() or not lief.is_elf(target):
        print(f"Wrong target! ({target})", file=sys.stderr)
        return 1

    if not interpreter.is_file() or not lief.is_elf(interpreter):
        print(f"Wrong interpreter! ({interpreter})", file=sys.stderr)
        return 1

    binary = lief.ELF.parse(target)
    if binary is None:
        print(f"Failed to parse '{target}' as ELF", file=sys.stderr)
        return 1

    if not binary.has_interpreter:
        print("The given target doesn't have an interpreter!", file=sys.stderr)
        return 1

    binary.interpreter = str(interpreter)

    output_path = output or Path(f"{target.name}_updated")

    output_path.unlink(missing_ok=True)

    binary.write(output_path)

    # Restore the execute bit that LIEF doesn't propagate.
    st = output_path.stat()
    output_path.chmod(st.st_mode | stat.S_IEXEC)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-o", "--output", help="Path to the rewritten binary", default=None, type=Path
    )
    parser.add_argument("target", metavar="<elf>", help="Target ELF file", type=Path)
    parser.add_argument(
        "interpreter",
        metavar="<interpreter>",
        help="Path to the new interpreter",
        type=Path,
    )

    args = parser.parse_args()
    return change_interpreter(args.target, args.interpreter, args.output)


if __name__ == "__main__":
    sys.exit(main())
