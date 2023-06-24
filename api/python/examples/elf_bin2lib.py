#!/usr/bin/env python
import argparse
import lief
import sys

def bin2lib(binary, address, output, name=""):
    if not binary.is_pie:
        print("It only works with PIE binaries")
        sys.exit(1)

    function = binary.add_exported_function(address, name)
    print("Function created:")
    print(function)
    binary.write(output)

def main():
    parser = argparse.ArgumentParser(description="")

    parser.add_argument("--name", "-n", default="", help="Name of the function to create")
    parser.add_argument("--output", "-o", default="libfoo.so", help="Output name. (Default: %(default)")

    parser.add_argument("binary", help="The target binary")
    parser.add_argument("address", type=lambda e: int(e, 0), help="Address of the function to export")


    args = parser.parse_args()
    binary = lief.parse(args.binary)
    bin2lib(binary, args.address, args.output, name=args.name)

if __name__ == "__main__":
    main()
