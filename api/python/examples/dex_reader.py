#!/usr/bin/env python
"""Pretty-print the structure of an Android DEX file.

Parses a ``.dex`` file with ``lief.DEX.parse`` and renders header,
classes, methods, fields, strings, types, prototypes and the map
list, selected by command-line flags.

Example:

    $ python dex_reader.py -a classes.dex
"""

import argparse
import shutil
import sys
import traceback

import lief
from lief import DEX

EXIT_STATUS = 0
_term_size = shutil.get_terminal_size((100, 100))
terminal_columns = _term_size.columns
terminal_rows = _term_size.lines


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
                exc_type, exc_value, exc_traceback = sys.exc_info()
                traceback.print_tb(exc_traceback)
                print("-" * 60)


@exceptions_handler(Exception)
def print_information(dexfile):
    print("== Information ==")
    print("DEX File version: {}".format(dexfile.version))
    print("")


@exceptions_handler(Exception)
def print_header(dexfile):
    print("== Header ==")
    print(dexfile.header)


@exceptions_handler(Exception)
def print_classes(dexfile):
    print("== Classes ==")
    for cls in dexfile.classes:
        print(cls)


@exceptions_handler(Exception)
def print_fields(dexfile):
    print("== Fields ==")
    for f in dexfile.fields:
        print(f)


@exceptions_handler(Exception)
def print_methods(dexfile):
    print("== Methods ==")
    for m in dexfile.methods:
        print(m)


@exceptions_handler(Exception)
def print_strings(dexfile):
    print("== Strings ==")
    for s in dexfile.strings:
        print(s)


@exceptions_handler(Exception)
def print_types(dexfile):
    print("== Types ==")
    for t in dexfile.types:
        print(t)


@exceptions_handler(Exception)
def print_prototypes(dexfile):
    print("== Prototypes ==")
    for t in dexfile.prototypes:
        print(t)


@exceptions_handler(Exception)
def print_map(dexfile):
    print("== Map ==")
    print(dexfile.map)


def main():
    parser = argparse.ArgumentParser(usage="%(prog)s [options] DEX files")
    parser.add_argument(
        "-a", "--all", action="store_true", dest="show_all", help="Show all information"
    )

    parser.add_argument(
        "-H", "--header", action="store_true", dest="show_header", help="Display header"
    )

    parser.add_argument(
        "-c",
        "--classes",
        action="store_true",
        dest="show_classes",
        help="Display classes",
    )

    parser.add_argument(
        "-f", "--fields", action="store_true", dest="show_fields", help="Display Fields"
    )

    parser.add_argument(
        "-m",
        "--methods",
        action="store_true",
        dest="show_methods",
        help="Display Methods",
    )

    parser.add_argument(
        "-s",
        "--strings",
        action="store_true",
        dest="show_strings",
        help="Display Strings",
    )

    parser.add_argument(
        "-t", "--types", action="store_true", dest="show_types", help="Display Types"
    )

    parser.add_argument(
        "-p",
        "--prototypes",
        action="store_true",
        dest="show_prototypes",
        help="Display Prototypes",
    )

    parser.add_argument(
        "-M", "--map", action="store_true", dest="show_map", help="Display Map"
    )

    parser.add_argument("file", metavar="<dex-file>", help="Target DEX File")

    logger_group = parser.add_argument_group("Logger")
    verbosity = logger_group.add_mutually_exclusive_group()

    verbosity.add_argument(
        "--debug",
        dest="main_verbosity",
        action="store_const",
        const=lief.logging.LEVEL.DEBUG,
    )

    verbosity.add_argument(
        "--trace",
        dest="main_verbosity",
        action="store_const",
        const=lief.logging.LEVEL.TRACE,
    )

    verbosity.add_argument(
        "--info",
        dest="main_verbosity",
        action="store_const",
        const=lief.logging.LEVEL.INFO,
    )

    verbosity.add_argument(
        "--warn",
        dest="main_verbosity",
        action="store_const",
        const=lief.logging.LEVEL.WARN,
    )

    verbosity.add_argument(
        "--err",
        dest="main_verbosity",
        action="store_const",
        const=lief.logging.LEVEL.ERROR,
    )

    verbosity.add_argument(
        "--critical",
        dest="main_verbosity",
        action="store_const",
        const=lief.logging.LEVEL.CRITICAL,
    )

    parser.set_defaults(main_verbosity=lief.logging.LEVEL.WARN)

    args = parser.parse_args()

    lief.logging.set_level(args.main_verbosity)

    dexfile = DEX.parse(args.file)
    if dexfile is None:
        print(f"Error: failed to parse '{args.file}' as DEX", file=sys.stderr)
        return 1

    print_information(dexfile)

    if args.show_header or args.show_all:
        print_header(dexfile)

    if (args.show_classes or args.show_all) and len(dexfile.classes) > 0:
        print_classes(dexfile)

    if (args.show_fields or args.show_all) and len(dexfile.fields) > 0:
        print_fields(dexfile)

    if (args.show_methods or args.show_all) and len(dexfile.methods) > 0:
        print_methods(dexfile)

    if (args.show_strings or args.show_all) and len(dexfile.strings) > 0:
        print_strings(dexfile)

    if (args.show_types or args.show_all) and len(dexfile.types) > 0:
        print_types(dexfile)

    if (args.show_prototypes or args.show_all) and len(dexfile.prototypes) > 0:
        print_prototypes(dexfile)

    if args.show_map or args.show_all:
        print_map(dexfile)

    return EXIT_STATUS


if __name__ == "__main__":
    sys.exit(main())
