#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about a Android OAT files
import sys
import os
import argparse
import traceback
import lief
from lief import OAT

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
def print_information(binary):
    print("== Information ==")
    format_str = "{:<30} {:<30}"
    format_hex = "{:<30} 0x{:<28x}"
    format_dec = "{:<30} {:<30d}"

    android_version = lief.OAT.android_version(binary.header.version)
    code_name       = lief.Android.code_name(android_version)
    version         = lief.Android.version_string(android_version)

    print("Version: {} - Android {} {}".format(binary.header.version, version, code_name))
    print("Number of dex files: {}".format(len(binary.oat_dex_files)))
    print("Number of classes: {}".format(len(binary.classes)))
    print("Number of methods: {}".format(len(binary.methods)))
    print("")


@exceptions_handler(Exception)
def print_header(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    print("== Header ==")
    header = binary.header
    print(header)

@exceptions_handler(Exception)
def print_dex_files(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    oat_dex_files = binary.oat_dex_files

    print("== Dex files ==")
    for oat_dex in oat_dex_files:
        print(oat_dex)

@exceptions_handler(Exception)
def print_classes(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    classes = binary.classes

    print("== Classes ==")
    for cls in classes:
        print(cls)

@exceptions_handler(Exception)
def print_methods(binary):
    format_str = "{:<33} {:<30}"
    format_hex = "{:<33} 0x{:<28x}"
    format_dec = "{:<33} {:<30d}"

    methods = binary.methods

    print("== Methods ==")
    for m in methods:
        print(m)


def main():
    parser = argparse.ArgumentParser(usage='%(prog)s [options] oat files')
    parser.add_argument('-a', '--all',
            action='store_true', dest='show_all',
            help='Show all information')

    parser.add_argument('-H', '--header',
            action='store_true', dest='show_header',
            help='Display header')

    parser.add_argument('-c', '--classes',
            action='store_true', dest='show_classes',
            help='Display classes')

    parser.add_argument('-d', '--dex',
            action='store_true', dest='show_dex',
            help='Display Dex files')

    parser.add_argument('-m', '--methods',
            action='store_true', dest='show_methods',
            help='Display Methods')

    parser.add_argument('-x', '--extract',
            action='store_true', dest='extract_dex',
            help='Extract DEX files')

    parser.add_argument("binary",
            metavar="<oat-file>",
            help='Target OAT File')

    args = parser.parse_args()


    binary = None
    try:
        binary = OAT.parse(args.binary)
    except lief.exception as e:
        print(e)
        sys.exit(1)

    print_information(binary)

    if args.show_header or args.show_all:
        print_header(binary)

    if (args.show_dex or args.show_all) and len(binary.oat_dex_files) > 0:
        print_dex_files(binary)

    if args.show_classes and len(binary.classes) > 0:
        print_classes(binary)

    if args.show_methods and len(binary.methods) > 0:
        print_methods(binary)

    sys.exit(EXIT_STATUS)


if __name__ == "__main__":
    main()
