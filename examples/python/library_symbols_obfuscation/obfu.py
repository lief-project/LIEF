#!/usr/bin/env python
import lief

libadd = lief.ELF.parse("./libadd.so")
binadd = lief.ELF.parse("./binadd.bin")

libadd_dynsym = libadd.dynamic_symbols
binadd_dynsym = binadd.dynamic_symbols

# Change add in the libary
for sym in libadd_dynsym:
    if sym.name == "add":
        sym.name = "abc"

# Change "add" in the binary
for sym in binadd_dynsym:
    if sym.name == "add":
        sym.name = "abc"


# change library name in the binary
for entry in binadd.dynamic_entries:
    if entry.tag == lief.ELF.NEEDED and entry.name == "libadd.so":
        entry.name = "libabc.so"


libadd.write("libabc.so");
binadd.write("binadd_obf.bin")


