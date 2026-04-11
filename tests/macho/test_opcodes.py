import pathlib

from utils import parse_macho

CURRENT_DIR = pathlib.Path(__file__).parent


def read_opcode_file(name):
    buff = (CURRENT_DIR / "opcodes" / name).read_text()
    buff = buff.replace("\r", "")
    return buff


def test_rebase_opcodes():
    target = parse_macho("MachO/MachO64_x86-64_binary_rebase-LLVM.bin").at(0)
    assert target is not None

    reference = read_opcode_file("MachO64_x86-64_binary_rebase-LLVM.rebase_opcodes")
    dyld_info = target.dyld_info
    assert dyld_info is not None
    value = dyld_info.show_rebases_opcodes
    value = value.replace("\r", "")
    assert reference == value


def test_lazy_bind_opcodes():
    target = parse_macho("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin").at(0)
    assert target is not None

    reference = read_opcode_file(
        "MachO64_x86-64_binary_lazy-bind-LLVM.lazy_bind_opcodes"
    )
    dyld_info = target.dyld_info
    assert dyld_info is not None
    value = dyld_info.show_lazy_bind_opcodes
    value = value.replace("\r", "")
    assert reference == value


def test_bind_opcodes():
    target = parse_macho("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin").at(0)
    assert target is not None

    reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.bind_opcodes")
    dyld_info = target.dyld_info
    assert dyld_info is not None
    value = dyld_info.show_bind_opcodes
    value = value.replace("\r", "")
    assert reference == value


def test_export_trie():
    target = parse_macho("MachO/MachO64_x86-64_binary_lazy-bind-LLVM.bin").at(0)
    assert target is not None

    reference = read_opcode_file("MachO64_x86-64_binary_lazy-bind-LLVM.export_trie")
    dyld_info = target.dyld_info
    assert dyld_info is not None
    value = dyld_info.show_export_trie
    value = value.replace("\r", "")

    assert reference == value
