#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about a ELF binary in the JSON format
#
# python elf_json.py /bin/ls
#
# {
#   "dynamic_entries": [
#        {
#            "library": "libcap.so.2",
#            "tag": "NEEDED",
#            "value": 1
#        },
#        {
#            "library": "libc.so.6",
#            "tag": "NEEDED",
#            "value": 74
#        },
# ...


import argparse
import sys
import lief
import json



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help='ELF binary')
    args = parser.parse_args()

    binary    = lief.parse(args.binary)
    json_data = json.loads(lief.to_json(binary))
    print(json.dumps(json_data, sort_keys = True, indent = 4))

if __name__ == "__main__":
    sys.exit(main())

