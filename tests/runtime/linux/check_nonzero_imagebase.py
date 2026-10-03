import argparse
import ctypes
import resource
from pathlib import Path

import lief
from lief.runtime import Memory


def check(library: Path, relocate: bool):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    binary = lief.ELF.parse(library)
    assert binary is not None
    symbol = binary.get_dynamic_symbol("module_probe")
    assert symbol is not None

    reservation = None
    if relocate:
        # Occupy the preferred base without replacing any existing mappings.
        reservation = Memory.mmap_hint(
            binary.imagebase,
            binary.virtual_size,
            Memory.ANONYMOUS | Memory.PRIVATE,
            Memory.READ,
        )
        assert reservation is not None

    try:
        native = ctypes.CDLL(str(library))
        assert native.module_probe() == 42
        address = ctypes.cast(native.module_probe, ctypes.c_void_p).value
        assert address is not None
        expected_base = address - symbol.value + binary.imagebase
        if relocate:
            assert expected_base != binary.imagebase

        listed = next(
            m
            for m in lief.runtime.modules()
            if m is not None and m.path == str(library)
        )
        assert isinstance(listed, lief.runtime.linux.Module)
        named = lief.runtime.module_from_name(library.name)
        assert isinstance(named, lief.runtime.linux.Module)
        from_handle = lief.runtime.linux.Module.from_handle(listed.handle)
        assert from_handle is not None
        opened = lief.runtime.linux.dlopen(library)
        assert opened is not None

        for module in (listed, named, from_handle, opened):
            assert module.imagebase == expected_base, (
                f"Expected base {expected_base:#x}, got {module.imagebase:#x}"
            )
            assert module.size == listed.size > 0
            assert module.contains(address)
            data = module.dump()
            assert len(data) == module.size
            assert data[:4] == b"\x7fELF"
            parsed = module.parse_from_memory()
            assert parsed is not None
            assert parsed.get_dynamic_symbol("module_probe") is not None
    finally:
        if reservation is not None:
            assert Memory.munmap(reservation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=Path)
    parser.add_argument("--relocate", action="store_true")
    args = parser.parse_args()
    check(args.library.resolve(), args.relocate)
