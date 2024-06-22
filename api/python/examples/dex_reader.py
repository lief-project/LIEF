#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about Android DEX files
import sys
import os
import argparse
import traceback
import lief
from lief import DEX

EXIT_STATUS = 0
terminal_rows, terminal_columns = 100, 100
try:
    terminal_rows, terminal_columns = os.popen('stty size', 'r').read().split()
except ValueError:
    pass


class exceptions_handler(object):
    func = None

    def __init__(self, exceptions, on_except_callback=None):
        self.exceptions         = exceptions
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
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"
    version = dexfile.version

    print("DEX File version: {}".format(version))
    print("")


@exceptions_handler(Exception)
def print_header(dexfile):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    print("== Header ==")
    header = dexfile.header
    print(header)

@exceptions_handler(Exception)
def print_classes(dexfile):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    classes = dexfile.classes

    print("== Classes ==")
    for cls in classes:
        print(cls)

@exceptions_handler(Exception)
def print_fields(dexfile):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    fields = dexfile.fields

    print("== Fields ==")
    for f in fields:
        print(f)

@exceptions_handler(Exception)
def print_methods(dexfile):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    methods = dexfile.methods

    print("== Methods ==")
    for m in methods:
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
    parser = argparse.ArgumentParser(usage='%(prog)s [options] DEX files')
    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Show all information')

    parser.add_argument('-H', '--header',
            action='store_true', dest='show_header',
            help='Display header')

    parser.add_argument('-c', '--classes',
            action='store_true', dest='show_classes',
            help='Display classes')

    parser.add_argument('-f', '--fields',
            action='store_true', dest='show_fields',
            help='Display Fields')

    parser.add_argument('-m', '--methods',
            action='store_true', dest='show_methods',
            help='Display Methods')

    parser.add_argument('-s', '--strings',
            action='store_true', dest='show_strings',
            help='Display Strings')

    parser.add_argument('-t', '--types',
            action='store_true', dest='show_types',
            help='Display Types')

    parser.add_argument('-p', '--prototypes',
            action='store_true', dest='show_prototypes',
            help='Display Prototypes')

    parser.add_argument('-M', '--map',
            action='store_true', dest='show_map',
            help='Display Map')

    parser.add_argument("file",
            metavar="<dex-file>",
            help='Target DEX File')

    logger_group = parser.add_argument_group('Logger')
    verbosity = logger_group.add_mutually_exclusive_group()

    verbosity.add_argument('--debug',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.DEBUG)

    verbosity.add_argument('--trace',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.TRACE)

    verbosity.add_argument('--info',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.INFO)

    verbosity.add_argument('--warn',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.WARN)

    verbosity.add_argument('--err',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.ERROR)

    verbosity.add_argument('--critical',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LEVEL.CRITICAL)

    parser.set_defaults(main_verbosity=lief.logging.LEVEL.WARN)

    args = parser.parse_args()

    lief.logging.set_level(args.main_verbosity)

    dexfile = DEX.parse(args.file)

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

    sys.exit(EXIT_STATUS)


if __name__ == "__main__":
    main()
