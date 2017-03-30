#!/usr/bin/env python
import lief
import sys

binary = lief.parse(sys.argv[1])
builder = lief.PE.Builder(binary)
builder.build_imports(True)
builder.patch_imports(True)
builder.build_relocations(False)
builder.build_tls(False)
builder.build_resources(False)
builder.build();

builder.write(sys.argv[2])
