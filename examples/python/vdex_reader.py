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

from lief import Logger
Logger.set_level(lief.LOGGING_LEVEL.INFO)


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

    args = parser.parse_args()


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
