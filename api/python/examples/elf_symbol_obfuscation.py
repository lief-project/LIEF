#!/usr/bin/env python
# -*- coding: utf-8 -*-


# In this example, we replace all symtab symbols in the .symtab
# with a random name.
#
# Example:
#
#     >>> readelf -s ./hello_c
#
#     28: 0600700 0 OBJECT  LOCAL  DEFAULT 19 __JCR_LIST__
#     29: 0400420 0 FUNC    LOCAL  DEFAULT 12 deregister_tm_clones
#     30: 0400460 0 FUNC    LOCAL  DEFAULT 12 register_tm_clones
#     31: 04004a0 0 FUNC    LOCAL  DEFAULT 12 __do_global_dtors_aux
#     32: 0600920 1 OBJECT  LOCAL  DEFAULT 24 completed.6940
#     33: 06006f8 0 OBJECT  LOCAL  DEFAULT 18 __do_global_dtors_aux_fin
#     ...
#
#     >>> python elf_symbol_obfuscation ./hello_c ./hello_c.obf
#
#     >>> readelf -s ./hello_c.obf
#
#     28: 0600700 0 OBJECT  LOCAL  DEFAULT 19 xnsffdfsryna
#     29: 0400420 0 FUNC    LOCAL  DEFAULT 12 wsadqwrubbmdugrxzwiv
#     30: 0400460 0 FUNC    LOCAL  DEFAULT 12 wrgeecrckeskyishte
#     31: 04004a0 0 FUNC    LOCAL  DEFAULT 12 pqhfpptwtqzuiefrwnwdk
#     32: 0600920 1 OBJECT  LOCAL  DEFAULT 24 vwevxfvdmcrjdv
#     33: 06006f8 0 OBJECT  LOCAL  DEFAULT 18 rksefyibghsyhbbnfikknpvzc



import lief
import sys
import random, string

def randomword(length):
   return ''.join(random.choice(string.ascii_lowercase) for i in range(length))

def randomize(binary, output):

    symbols = binary.symtab_symbols
    if len(symbols) == 0:
        print("No symbols")
        return
    for symbol in symbols:
        symbol.name = randomword(len(symbol.name))

    binary.write(output)

def main():
    if len(sys.argv) != 3:
        print("Usage:", sys.argv[0], "<elf binary> <output binary>")
        sys.exit(-1)

    binary = lief.parse(sys.argv[1])
    randomize(binary, sys.argv[2])

if __name__ == '__main__':
    main()


