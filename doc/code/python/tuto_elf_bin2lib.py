import sys

import lief


def export_function(crackme101: lief.ELF.Binary) -> None:
    # lief-doc: export-start
    crackme101: lief.ELF.Binary

    addr = crackme101.get_function_address("check_found")  # 0x72A
    assert isinstance(addr, int)
    crackme101.add_exported_function(addr, "check_found")
    crackme101.write("libcrackme101.so")
    # lief-doc: export-end


def remove_pie() -> None:
    # lief-doc: remove-pie-start
    path = sys.argv[1]
    bin_ = lief.parse(path)
    assert isinstance(bin_, lief.ELF.Binary)
    bin_[lief.ELF.DynamicEntry.TAG.FLAGS_1].remove(lief.ELF.DynamicEntryFlags.FLAG.PIE)
    bin_.write(path + ".patched")
    # lief-doc: remove-pie-end
