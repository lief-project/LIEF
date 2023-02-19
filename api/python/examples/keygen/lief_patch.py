#!/usr/bin/env python2

# Description
# -----------
# Patch binary to remove anti-debug

import sys
from lief import ELF
import distorm3


def remove_anti_debug(binary):
    patch        = [0x83, 0xf8, 0xff, 0x90, 0x90] # cmp eax, 0xFFFFFFFF
    ep           = binary.header.entrypoint
    text_section = binary.section_from_virtual_address(ep)
    code         = "".join(map(chr, text_section.content))
    iterable     = distorm3.DecodeGenerator(text_section.virtual_address, code, distorm3.Decode32Bits)
    for (offset, size, instruction, hexdump) in iterable:
        if "CMP EAX, 0x3000" in instruction:
            # Patch 3d 00 30 00 00
            binary.patch_address(offset, patch)
            print("[PATCH] %.8x: %-32s %s" % (offset, hexdump, instruction))

    # Distorm didn't get this one
    binary.patch_address(0x804936B, patch)

def crack_it(binary):
    # user: what you wants
    # serial: any NUMBER

    patch1 = [0x31, 0xD2] # xor edx, edx
    patch2 = [0x31, 0xC0] # xor eax, eax

    binary.patch_address(0x8049486, patch1) # xor edx, edi --> xor edx, edx
    binary.patch_address(0x8049488, patch2) # xor eax, ecx --> xor eax, eax

def main(argv):
    binary = ELF.parse("./KeygenMe")
    remove_anti_debug(binary)
    crack_it(binary)
    binary.write("./KeygenMe.crack")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))




