#!/usr/bin/env python
import lief
import pathlib
from utils import get_sample

def test_exports_trie():
    target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_exports-trie-LLVM.bin'))
    assert target.has_dyld_info
    exports = target.dyld_info.exports

    assert len(exports) == 6

    assert exports[0].address == 0
    assert exports[0].symbol.name == "_malloc"

    assert exports[1].address == 0
    assert exports[1].symbol.name == "_myfree"

    assert exports[2].address == 0xf70
    assert exports[2].symbol.name == "_myWeak"

    assert exports[3].address == 0x1018
    assert exports[3].symbol.name == "_myTLV"

    assert exports[4].address == 0x12345678
    assert exports[4].symbol.name == "_myAbs"

    assert exports[5].address == 0xf60
    assert exports[5].symbol.name == "_foo"


def test_bind():
    target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_bind-LLVM.bin'))
    assert target.has_dyld_info
    bindings = target.dyld_info.bindings

    assert len(bindings) == 7

    assert bindings[0].binding_class == lief.MachO.BINDING_CLASS.STANDARD
    assert bindings[0].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[0].address == 0x1028
    assert bindings[0].symbol.name == "_any"
    assert bindings[0].segment.name == "__DATA"
    assert bindings[0].library_ordinal == -2

    assert bindings[1].binding_class == lief.MachO.BINDING_CLASS.STANDARD
    assert bindings[1].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[1].address == 0x1020
    assert bindings[1].symbol.name == "_fromApp"
    assert bindings[1].segment.name == "__DATA"
    assert bindings[1].library_ordinal == -1

    assert bindings[2].binding_class == lief.MachO.BINDING_CLASS.STANDARD
    assert bindings[2].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[2].address == 0x1018
    assert bindings[2].symbol.name == "_myfunc"
    assert bindings[2].segment.name == "__DATA"
    assert bindings[2].library_ordinal == 0

    assert bindings[3].binding_class == lief.MachO.BINDING_CLASS.STANDARD
    assert bindings[3].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[3].address == 0x1000
    assert bindings[3].symbol.name == "_foo"
    assert bindings[3].segment.name == "__DATA"
    assert bindings[3].library.name == "libfoo.dylib"

    assert bindings[4].binding_class == lief.MachO.BINDING_CLASS.STANDARD
    assert bindings[4].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[4].address == 0x1008
    assert bindings[4].symbol.name == "_bar"
    assert bindings[4].segment.name == "__DATA"
    assert bindings[4].library.name == "libbar.dylib"

    assert bindings[5].binding_class == lief.MachO.BINDING_CLASS.STANDARD
    assert bindings[5].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[5].address == 0x1010
    assert bindings[5].symbol.name == "_malloc"
    assert bindings[5].segment.name == "__DATA"
    assert bindings[5].library.name == "/usr/lib/libSystem.B.dylib"


    # From Weak bind
    assert bindings[6].binding_class == lief.MachO.BINDING_CLASS.WEAK
    assert bindings[6].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[6].address == 0x1000
    assert bindings[6].symbol.name == "_foo"
    assert bindings[6].segment.name == "__DATA"


def test_lazy_bind():
    target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin'))
    assert target.has_dyld_info

    bindings = list(target.dyld_info.bindings)[1:] # Skip the 1st one (Standard one)
    assert len(bindings) == 3

    assert bindings[0].binding_class == lief.MachO.BINDING_CLASS.LAZY
    assert bindings[0].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[0].address == 0x100001010
    assert bindings[0].symbol.name == "_foo"
    assert bindings[0].segment.name == "__DATA"
    assert bindings[0].library.name == "libfoo.dylib"

    assert bindings[1].binding_class == lief.MachO.BINDING_CLASS.LAZY
    assert bindings[1].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[1].address == 0x100001018
    assert bindings[1].symbol.name == "_bar"
    assert bindings[1].segment.name == "__DATA"
    assert bindings[1].library.name == "libbar.dylib"

    assert bindings[2].binding_class == lief.MachO.BINDING_CLASS.LAZY
    assert bindings[2].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[2].address == 0x100001020
    assert bindings[2].symbol.name == "_malloc"
    assert bindings[2].segment.name == "__DATA"
    assert bindings[2].library.name == "/usr/lib/libSystem.B.dylib"


def test_rebases():
    target = lief.parse(get_sample('MachO/MachO64_x86-64_binary_rebase-LLVM.bin'))
    assert target.has_dyld_info

    relocations = target.relocations

    assert len(relocations) == 10

    assert relocations[0].address == 0x00001010
    assert not relocations[0].pc_relative
    assert relocations[0].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[0].section.name == "__data"
    assert relocations[0].segment.name == "__DATA"

    assert relocations[1].address == 0x00001028
    assert not relocations[1].pc_relative
    assert relocations[1].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[1].section.name == "__data"
    assert relocations[1].segment.name == "__DATA"

    assert relocations[2].address == 0x00001030
    assert not relocations[2].pc_relative
    assert relocations[2].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[2].section.name == "__data"
    assert relocations[2].segment.name == "__DATA"

    assert relocations[3].address == 0x00001038
    assert not relocations[3].pc_relative
    assert relocations[3].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[3].section.name == "__data"
    assert relocations[3].segment.name == "__DATA"

    assert relocations[4].address == 0x00001040
    assert not relocations[4].pc_relative
    assert relocations[4].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[4].section.name == "__data"
    assert relocations[4].segment.name == "__DATA"

    assert relocations[5].address == 0x00001258
    assert not relocations[5].pc_relative
    assert relocations[5].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[5].section.name == "__data"
    assert relocations[5].segment.name == "__DATA"


    assert relocations[6].address == 0x00001278
    assert not relocations[6].pc_relative
    assert relocations[6].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[6].section.name == "__mystuff"
    assert relocations[6].segment.name == "__DATA"

    assert relocations[7].address == 0x00001288
    assert not relocations[7].pc_relative
    assert relocations[7].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[7].section.name == "__mystuff"
    assert relocations[7].segment.name == "__DATA"

    assert relocations[8].address == 0x00001298
    assert not relocations[8].pc_relative
    assert relocations[8].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[8].section.name == "__mystuff"
    assert relocations[8].segment.name == "__DATA"

    assert relocations[9].address == 0x000012A8
    assert not relocations[9].pc_relative
    assert relocations[9].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[9].section.name == "__mystuff"
    assert relocations[9].segment.name == "__DATA"

def test_threaded_opcodes(tmp_path):
    bin_path = pathlib.Path(get_sample('MachO/FatMachO64_x86-64_arm64_binary_ls.bin'))
    target = lief.MachO.parse(bin_path.as_posix())
    target = target.take(lief.MachO.CPU_TYPES.ARM64)
    assert target.has_dyld_info

    relocations = target.relocations
    bindings = target.dyld_info.bindings

    assert len(relocations) == 39
    assert len(bindings) == 82

    assert relocations[38].address == 0x10000c008
    assert not relocations[38].pc_relative
    assert relocations[38].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[38].section.name == "__data"
    assert relocations[38].segment.name == "__DATA"

    assert bindings[81].binding_class == lief.MachO.BINDING_CLASS.THREADED
    assert bindings[81].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[81].address == 0x100008288
    assert bindings[81].symbol.name == "_optind"
    assert bindings[81].segment.name == "__DATA_CONST"
    assert bindings[81].library.name == "/usr/lib/libSystem.B.dylib"

    output_path = f"{tmp_path}/{bin_path.name}"
    lief.logging.set_level(lief.logging.LOGGING_LEVEL.DEBUG)
    target.write(output_path)
    lief.logging.set_level(lief.logging.LOGGING_LEVEL.INFO)

    print(output_path)
    fat_written_target = lief.MachO.parse(output_path)
    written_target = fat_written_target.take(lief.MachO.CPU_TYPES.ARM64)
    for r in written_target.relocations:
        print(r)

    relocations = written_target.relocations
    bindings = written_target.dyld_info.bindings

    checked, err = lief.MachO.check_layout(written_target)
    assert checked, err

    assert len(relocations) == 39
    assert len(bindings) == 82

    assert relocations[38].address == 0x10000c008
    assert not relocations[38].pc_relative
    assert relocations[38].type == int(lief.MachO.REBASE_TYPES.POINTER)
    assert relocations[38].section.name == "__data"
    assert relocations[38].segment.name == "__DATA"

    assert bindings[81].binding_class == lief.MachO.BINDING_CLASS.THREADED
    assert bindings[81].binding_type == lief.MachO.BIND_TYPES.POINTER
    assert bindings[81].address == 0x100008288
    assert bindings[81].symbol.name == "_optind"
    assert bindings[81].segment.name == "__DATA_CONST"
    assert bindings[81].library.name == "/usr/lib/libSystem.B.dylib"
