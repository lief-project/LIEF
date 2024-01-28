#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Print information about a DEX file in the JSON format

import argparse
import sys
import lief
import json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='VDEX file')
    args = parser.parse_args()

    if not lief.is_vdex(args.file):
        print("{} is not a VDEX file".format(args.file))
        return 1
    dexfile   = lief.VDEX.parse(args.file)
    json_data = json.loads(lief.to_json(dexfile))
    print(json.dumps(json_data, sort_keys = True, indent = 4))

if __name__ == "__main__":
    sys.exit(main())

