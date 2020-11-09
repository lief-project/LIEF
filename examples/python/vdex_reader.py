#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about Android VDEX files
import sys
import os
import argparse
import traceback
import lief
from lief import VDEX, DEX

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
def print_information(vdexfile):
    print("== Information ==")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"
    version = vdexfile.header.version

    print("VDEX File version: {}".format(version))
    print("")


@exceptions_handler(Exception)
def print_header(vdexfile):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    print("== Header ==")
    header = vdexfile.header
    print(header)

def main():
    parser = argparse.ArgumentParser(usage='%(prog)s [options] VDEX files')
    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Show all information')

    parser.add_argument('-H', '--header',
            action='store_true', dest='show_header',
            help='Display header')

    parser.add_argument("file",
            metavar="<dex-file>",
            help='Target DEX File')
    # Logging setup
    logger_group = parser.add_argument_group('Logger')
    verbosity = logger_group.add_mutually_exclusive_group()

    verbosity.add_argument('--debug',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.DEBUG)

    verbosity.add_argument('--trace',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.TRACE)

    verbosity.add_argument('--info',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.INFO)

    verbosity.add_argument('--warn',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.WARNING)

    verbosity.add_argument('--err',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.ERROR)

    verbosity.add_argument('--critical',
            dest='main_verbosity',
            action='store_const',
            const=lief.logging.LOGGING_LEVEL.CRITICAL)

    parser.set_defaults(main_verbosity=lief.logging.LOGGING_LEVEL.WARNING)

    args = parser.parse_args()

    lief.logging.set_level(args.main_verbosity)

    vdexfile = None
    try:
        vdexfile = DEX.parse(args.file)
    except lief.exception as e:
        print(e)
        sys.exit(1)

    print_information(vdexfile)

    if args.show_header or args.show_all:
        print_header(vdexfile)

    sys.exit(EXIT_STATUS)


if __name__ == "__main__":
    main()
