#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Description
# -----------
# Remove the section table from an ELF binary
# so that some tools are blow minded (e.g. gdb)
#
# Example:
# $ python elf_remove_section_table.py /bin/ls ls_without_sections
# $ ls
# elf_remove_section_table.py ls_without_sections
# $ ls_without_sections
# $ elf_remove_section_table.py ls_without_sections
# $ readelf -S ls_without_sections
#
# Il n'y a pas de section dans ce fichier.
# $ gdb ls_without_sections
# "ls_without_sections": not in executable format: File format not recognized

import sys
import lief
from lief import ELF

def remove_section_table(filename, output):
    binary  = lief.ELF.parse(filename) # Build an ELF binary

    header = binary.header
    header.section_header_offset = 0;
    header.numberof_sections     = 0;

    binary.write(output);

def main():
    if len(sys.argv) != 3:
        print("Usage: {} <elf binary> <output>".format(sys.argv[0]))
        sys.exit(1)

    remove_section_table(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
