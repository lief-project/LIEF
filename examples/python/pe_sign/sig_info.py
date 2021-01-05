#!/usr/bin/env python
import lief
import argparse
import json
import sys
from prettyprinter import pprint

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pe_file")

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

    binary = None
    try:
        binary = lief.PE.parse(args.pe_file)
    except lief.exception as e:
        print(e)
        sys.exit(1)

    for sig in binary.signatures:
        print(sig)

if __name__ == "__main__":
    main()
