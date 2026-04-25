#!/usr/bin/env python
"""Pretty-print the structure of an Android VDEX file.

Parses a ``.vdex`` container with ``lief.VDEX.parse`` and renders the
header and (optionally) the embedded DEX files.

Example:

    $ python vdex_reader.py -a primary.vdex
"""

import argparse
import sys
import traceback

import lief
from lief import VDEX

EXIT_STATUS = 0


class exceptions_handler(object):
    func = None

    def __init__(self, exceptions, on_except_callback=None):
        self.exceptions = exceptions
        self.on_except_callback = on_except_callback

    def __call__(self, *args, **kwargs):
        if self.func is None:
            self.func = args[0]
            return self
        try:
            return self.func(*args, **kwargs)
        except self.exceptions as e:
            global EXIT_STATUS
            print("{} raised: {}".format(self.func.__name__, e))
            EXIT_STATUS = 1
            if self.on_except_callback is not None:
                self.on_except_callback(e)
            else:
                print("-" * 60)
                print("Exception in {}: {}".format(self.func.__name__, e))
                traceback.print_exc()
                print("-" * 60)


@exceptions_handler(Exception)
def print_information(vdexfile):
    print("== Information ==")
    print("VDEX File version: {}".format(vdexfile.header.version))
    print("")


@exceptions_handler(Exception)
def print_header(vdexfile):
    print("== Header ==")
    print(vdexfile.header)


@exceptions_handler(Exception)
def print_dex_files(vdexfile):
    print("== Embedded DEX files ==")
    for dexfile in vdexfile.dex_files:
        print(dexfile)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-a", "--all", action="store_true", dest="show_all", help="Show all information"
    )
    parser.add_argument(
        "-H", "--header", action="store_true", dest="show_header", help="Display header"
    )
    parser.add_argument(
        "-d", "--dex", action="store_true", dest="show_dex", help="Display embedded DEX files"
    )
    parser.add_argument("file", metavar="<vdex-file>", help="Target VDEX file")

    logger_group = parser.add_argument_group("Logger")
    verbosity = logger_group.add_mutually_exclusive_group()
    verbosity.add_argument("--debug", dest="main_verbosity", action="store_const",
                           const=lief.logging.LEVEL.DEBUG)
    verbosity.add_argument("--trace", dest="main_verbosity", action="store_const",
                           const=lief.logging.LEVEL.TRACE)
    verbosity.add_argument("--info", dest="main_verbosity", action="store_const",
                           const=lief.logging.LEVEL.INFO)
    verbosity.add_argument("--warn", dest="main_verbosity", action="store_const",
                           const=lief.logging.LEVEL.WARN)
    verbosity.add_argument("--err", dest="main_verbosity", action="store_const",
                           const=lief.logging.LEVEL.ERROR)
    verbosity.add_argument("--critical", dest="main_verbosity", action="store_const",
                           const=lief.logging.LEVEL.CRITICAL)
    parser.set_defaults(main_verbosity=lief.logging.LEVEL.WARN)

    args = parser.parse_args()
    lief.logging.set_level(args.main_verbosity)

    vdexfile = VDEX.parse(args.file)
    if vdexfile is None:
        print(f"Error: failed to parse '{args.file}' as VDEX", file=sys.stderr)
        return 1

    print_information(vdexfile)

    if args.show_header or args.show_all:
        print_header(vdexfile)

    if args.show_dex or args.show_all:
        print_dex_files(vdexfile)

    return EXIT_STATUS


if __name__ == "__main__":
    sys.exit(main())
