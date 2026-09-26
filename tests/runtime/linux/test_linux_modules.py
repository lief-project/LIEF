import ctypes

import lief
import pytest
from lief.runtime import Memory
from utils import get_sample, parse_elf, resolve_runtime_library

if not lief.runtime.enabled:
    pytest.skip("skipping: needs runtime support", allow_module_level=True)

if lief.runtime.platform != lief.runtime.PLATFORMS.LINUX:
    pytest.skip("skipping: linux only", allow_module_level=True)


@pytest.mark.runtime
def test_list_modules():
    modules = [m for m in lief.runtime.modules() if m is not None]
    assert len(modules) > 0

    assert all(m.imagebase > 0 for m in modules if m.name)
    assert all(isinstance(m, lief.runtime.linux.Module) for m in modules)

    lief_module = [m for m in modules if m.name in {"_lief.so", "_lief_extended.so"}]
    assert len(lief_module) == 1
    assert len(lief_module[0].path) > 0
    assert lief_module[0].size > 0


@pytest.mark.runtime
def test_handle_and_dlsym():
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None
    assert libc.handle is not None
    assert libc.dlsym("malloc") is not None
    assert libc.dlsym("__lief_does_not_exist__") is None

    libc_mod = lief.runtime.linux.Module.from_handle(libc.handle)
    assert libc_mod is not None
    assert libc_mod.imagebase == libc.imagebase

    library = resolve_runtime_library("runtime-base-addr")
    module = lief.runtime.linux.dlopen(library)
    assert module is not None
    listed = next(
        m for m in lief.runtime.modules() if m is not None and m.path == str(library)
    )
    assert module.imagebase == listed.imagebase
    assert module.size == listed.size > 0
    mod_from_hdl = lief.runtime.linux.Module.from_handle(module.handle)
    assert mod_from_hdl is not None
    assert mod_from_hdl.imagebase == module.imagebase
    assert mod_from_hdl.size == module.size


@pytest.mark.runtime
@pytest.mark.private
@pytest.mark.linux("x86_64")
@pytest.mark.parametrize(
    ("library", "has_phdr"),
    [
        ("libmodule-no-phdr.so", False),
        ("libmodule-with-phdr.so", True),
    ],
)
@pytest.mark.parametrize("relocate", [False, True], ids=["preferred", "relocated"])
def test_nonzero_imagebase(library: str, has_phdr: bool, relocate: bool):
    import resource

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    target_lib = get_sample(f"private/ELF/static2dyn/{library}")

    binary = parse_elf(target_lib)
    assert binary.imagebase == 0x1000000
    assert (binary.get(lief.ELF.Segment.TYPE.PHDR) is not None) == has_phdr

    symbol = binary.get_dynamic_symbol("module_probe")
    assert symbol is not None

    reservation = None
    if relocate:
        # For the binary to use a different imagebase
        reservation = Memory.mmap_hint(
            binary.imagebase,
            binary.virtual_size,
            Memory.ANONYMOUS | Memory.PRIVATE,
            Memory.READ,
        )
        assert reservation is not None

    try:
        native = ctypes.CDLL(target_lib)
        assert native.module_probe() == 42
        address = ctypes.cast(native.module_probe, ctypes.c_void_p).value
        assert address is not None
        expected_base = address - symbol.value + binary.imagebase

        if relocate:
            assert expected_base != binary.imagebase

        mod = lief.runtime.module_from_name(library)

        assert isinstance(mod, lief.runtime.linux.Module)
        from_handle = lief.runtime.linux.Module.from_handle(mod.handle)
        assert from_handle is not None
        opened = lief.runtime.linux.dlopen(target_lib)
        assert opened is not None

        for module in (mod, from_handle, opened):
            assert module.imagebase == expected_base, (
                f"Expected base {expected_base:#x}, got {module.imagebase:#x}"
            )
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


@pytest.mark.runtime
def test_parse_from_path():
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None

    binary = libc.parse_from_path()
    assert isinstance(binary, lief.ELF.Binary)
    assert binary.entrypoint > 0

    binary = libc.parse_from_path(lief.ELF.ParserConfig.all)
    assert isinstance(binary, lief.ELF.Binary)


def test_parse_from_memory():
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None

    libc.parse_from_memory()
    libc.parse_from_memory(lief.ELF.ParserConfig.all)


@pytest.mark.runtime
def test_dump(tmp_path):
    libc = next(
        (
            m
            for m in lief.runtime.modules()
            if isinstance(m, lief.runtime.linux.Module) and m.name.startswith("libc")
        ),
        None,
    )
    assert libc is not None

    data = libc.dump()
    assert isinstance(data, bytes)
    assert len(data) == libc.size
    assert data[:4] == b"\x7fELF"

    out = tmp_path / "libc.dump"
    written = libc.dump(str(out))
    assert isinstance(written, bytes)
    assert len(written) == libc.size
    assert written[:4] == b"\x7fELF"
    assert out.read_bytes() == written

    elf = lief.ELF.parse_from_dump(written, libc.imagebase)
    assert isinstance(elf, lief.ELF.Binary)
