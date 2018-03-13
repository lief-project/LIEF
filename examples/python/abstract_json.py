#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Dump abstract informations in a JSON format
# see: abstract_reader.py

import argparse
import sys
import lief
import json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help = 'A binary')
    args = parser.parse_args()

    binary    = lief.parse(args.binary)
    json_data = json.loads(lief.to_json_from_abstract(binary))
    print(json.dumps(json_data, sort_keys = True, indent = 4))

if __name__ == "__main__":
    sys.exit(main())

