#!/usr/bin/env python
import lief
import argparse
import os
import stat
import sys

def change_interpreter(target, interpreter, output=None):
    if not os.path.isfile(target) or not lief.is_elf(target):
        print("Wrong target! ({})".format(target))
        return 1


    if not os.path.isfile(interpreter) or not lief.is_elf(interpreter):
        print("Wrong interpreter! ({})".format(interpreter))
        return 1

    binary = lief.ELF.parse(target)
    if not binary.has_interpreter:
        print("The given target doesn't have interpreter!")
        return 1

    binary.interpreter = interpreter

    output_path = output
    if output_path is None:
        output_path = os.path.basename(target)
        output_path += "_updated"

    if os.path.isfile(output_path):
        os.remove(output_path)

    binary.write(output_path)

    # Set as executable
    st = os.stat(output_path)
    os.chmod(output_path, st.st_mode | stat.S_IEXEC)
    return 0


def main():
    parser = argparse.ArgumentParser(description='Change the ELF interpreter of the given binary')


    parser.add_argument("-o", "--output",
            help   = 'Path to the binary rewritten',
            action = 'store',
            default = None)

    parser.add_argument("target",
            metavar="<elf>",
            help='Target ELF file')

    parser.add_argument("interpreter",
            metavar="<interpreter>",
            help='Path to the new interpreter')


    args = parser.parse_args()

    status = change_interpreter(args.target, args.interpreter, args.output)
    sys.exit(status)


if __name__ == "__main__":
    main()


