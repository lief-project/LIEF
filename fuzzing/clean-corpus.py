#!/usr/bin/env python
import sys
import os

def is_elf(file):
    magic = None
    with open(file, 'rb') as f:
        raw = f.read()
        magic = raw[:4]
    return magic[0] == 0x7F and \
           magic[1] == ord('E') and \
           magic[2] == ord('L') and \
           magic[3] == ord('F')

def is_pe(file):
    magic = None
    with open(file, 'rb') as f:
        raw = f.read()
        magic = raw[:2]
    return magic[0] == ord('M') and \
           magic[1] == ord('Z')

def is_macho(file):
    magic = None
    with open(file, 'rb') as f:
        raw = f.read()
        magic = raw[:4]
    magic = list(magic)

    magics = [
            [0xFE, 0xED, 0xFA, 0xCE],
            [0xCE, 0xFA, 0xED, 0xFE],
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xCF, 0xFA, 0xED, 0xFE],
            [0xCA, 0xFE, 0xBA, 0xBE],
            [0xBE, 0xBA, 0xFE, 0xCA],
            ]
    return any(m == magic for m in magics)

def clean(directory):
    whitelist = [".git"]
    for dirname, subdir, files in os.walk(directory):

        if any(d in dirname for d in whitelist):
            continue

        for f in files:
            fullpath = os.path.join(dirname, f)

            if not (is_elf(fullpath)  or is_pe(fullpath) or is_macho(fullpath)):
                print("Removing '{}'".format(fullpath))
                try:
                    os.remove(fullpath)
                except Exception as e:
                    print("Error: {}".format(e))


def main():
    if len(sys.argv) != 2:
        print("Usage: {} <corpus>".format(sys.argv[0]))
        return 1
    clean(sys.argv[1])
    return 0

if __name__ == "__main__":
    main()



