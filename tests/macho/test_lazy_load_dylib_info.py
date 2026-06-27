import struct
from pathlib import Path

import lief
import pytest
from utils import check_layout, get_sample, parse_macho


def _get_lazy_loads(macho: lief.MachO.Binary) -> list[lief.MachO.LazyLoadDylibInfo]:
    """
    Internal helper to collect all the LazyLoadDylibInfo
    """
    infos = list(macho.lazy_load_dylib_infos)

    from_commands = [
        cmd for cmd in macho.commands if isinstance(cmd, lief.MachO.LazyLoadDylibInfo)
    ]
    assert [i.load_path for i in infos] == [c.load_path for c in from_commands]
    return infos


def _check_xpcproxy_infos(macho: lief.MachO.Binary, *, original: bool):
    """
    Basic check against the LazyLoadDylibInfo commands of xpcproxy
    """
    infos = _get_lazy_loads(macho)
    assert len(infos) == 2

    first = macho.lazy_load_dylib_infos[0]
    assert first is not None
    assert first.load_path == infos[0].load_path

    xpc_support = infos[0]
    if original:
        assert xpc_support.data_offset == 0x1D650
    assert xpc_support.data_size == 0x88
    assert (
        xpc_support.load_path
        == "/System/Library/PrivateFrameworks/XPCSupport.framework/Versions/A/XPCSupport"
    )
    assert xpc_support.flags == 0x1
    assert xpc_support.may_be_missing
    assert xpc_support.pointer_format == 9
    assert xpc_support.flag_image_offset == 0x18050
    assert xpc_support.chain_start_image_offset == 0x18020
    assert xpc_support.symbols == ["_xpc_support_copy_bundle_path"]
    assert "LAZY_LOAD_DYLIB_INFO" in str(xpc_support)
    assert len(bytes(xpc_support.content)) == 0x88

    xpc_fixups = list(xpc_support.fixups)
    assert len(xpc_fixups) == 1
    assert xpc_fixups[0].address == 0x100018020
    assert xpc_fixups[0].ordinal == 0
    assert xpc_fixups[0].symbol == "_xpc_support_copy_bundle_path"
    assert xpc_fixups[0].is_auth

    cryptex = infos[1]
    if original:
        assert cryptex.data_offset == 0x1D6D8
    assert cryptex.data_size == 0x110
    assert cryptex.load_path == "/usr/lib/libcryptex_trampoline.dylib"
    assert cryptex.flags == 0x1
    assert cryptex.may_be_missing
    assert cryptex.pointer_format == 9
    assert cryptex.flag_image_offset == 0x18054
    assert cryptex.chain_start_image_offset == 0x18000
    assert cryptex.symbols == [
        "_cryptex_trampoline_upgrade_wait",
        "_cryptex_trampoline_upgrade_wait_options_create",
        "_cryptex_trampoline_upgrade_wait_options_destroy",
        "_cryptex_trampoline_upgrade_wait_options_set_cryptex_name",
    ]
    assert len(bytes(cryptex.content)) == 0x110

    cryptex_fixups = list(cryptex.fixups)
    assert [f.symbol for f in cryptex_fixups] == cryptex.symbols
    assert [f.ordinal for f in cryptex_fixups] == [0, 1, 2, 3]
    assert all(f.is_auth for f in cryptex_fixups)
    assert [f.address for f in cryptex_fixups] == [
        0x100018000,
        0x100018008,
        0x100018010,
        0x100018018,
    ]

    # The two payloads adjacent in __LINKEDIT
    assert cryptex.data_offset == xpc_support.data_offset + xpc_support.data_size


@pytest.mark.private
def test_lazy_load_dylib_info(tmp_path: Path):
    bin_path = Path(get_sample("private/MachO/xpcproxy"))
    macho = parse_macho(bin_path).at(0)
    assert macho is not None

    check_layout(macho)

    _check_xpcproxy_infos(macho, original=True)

    # Keep the original payloads to make sure the write process preserves them
    original = [bytes(info.content) for info in _get_lazy_loads(macho)]

    output = tmp_path / bin_path.name
    macho.write(output)

    new = parse_macho(output).at(0)
    assert new is not None

    check_layout(new)

    _check_xpcproxy_infos(new, original=False)

    rebuilt = [bytes(info.content) for info in _get_lazy_loads(new)]
    assert rebuilt == original


@pytest.mark.private
def test_lazy_load_dylib_info_shift(tmp_path: Path):
    bin_path = Path(get_sample("private/MachO/xpcproxy"))
    macho = parse_macho(bin_path).at(0)
    assert macho is not None

    infos = _get_lazy_loads(macho)

    before_addr = [[f.address for f in info.fixups] for info in infos]

    plain = tmp_path / "plain"
    plain_macho = parse_macho(bin_path).at(0)
    assert plain_macho is not None
    plain_macho.write(plain)
    plain_macho = parse_macho(plain).at(0)
    assert plain_macho is not None

    before_dataoff = [i.data_offset for i in _get_lazy_loads(plain_macho)]

    shift = 0x4000
    macho.shift(shift)

    out = tmp_path / bin_path.name
    macho.write(out)

    new_macho = parse_macho(out).at(0)
    assert new_macho is not None
    check_layout(new_macho)

    infos = _get_lazy_loads(new_macho)
    for info, addrs in zip(infos, before_addr):
        assert [f.address for f in info.fixups] == [a + shift for a in addrs]

    for info, off in zip(infos, before_dataoff):
        assert info.data_offset == off + shift


@pytest.mark.private
def test_lazy_load_dylib_info_modify(tmp_path: Path):
    bin_path = Path(get_sample("private/MachO/xpcproxy"))
    macho = parse_macho(bin_path).at(0)
    assert macho is not None

    infos = _get_lazy_loads(macho)

    cryptex_path_before = infos[1].load_path
    cryptex_symbols_before = list(infos[1].symbols)
    cryptex_content_before = bytes(infos[1].content)

    xpc = infos[0]
    xpc.load_path = "/usr/lib/relocated_framework.dylib"
    xpc.may_be_missing = False  # clears flag bit 0
    xpc.flag_image_offset = 0x12345
    xpc.symbols = ["_brand_new_symbol", "_second_symbol"]
    xpc.add_symbol("_third_symbol")

    output = tmp_path / bin_path.name
    macho.write(output)

    new = parse_macho(output).at(0)
    assert new is not None
    check_layout(new)

    new_infos = _get_lazy_loads(new)
    new_xpc = new_infos[0]
    assert new_xpc.load_path == "/usr/lib/relocated_framework.dylib"
    assert new_xpc.flags == 0
    assert not new_xpc.may_be_missing
    assert new_xpc.symbols == [
        "_brand_new_symbol",
        "_second_symbol",
        "_third_symbol",
    ]
    assert new_xpc.data_size == len(bytes(new_xpc.content))

    new_fixups = list(new_xpc.fixups)
    assert len(new_fixups) == 1
    assert new_fixups[0].ordinal == 0
    assert new_fixups[0].symbol == "_brand_new_symbol"

    new_cryptex = new_infos[1]
    assert new_cryptex.load_path == cryptex_path_before
    assert list(new_cryptex.symbols) == cryptex_symbols_before
    assert bytes(new_cryptex.content) == cryptex_content_before

    new_xpc.may_be_missing = True
    assert new_xpc.flags & 0x1
    new_xpc.may_be_missing = False
    assert new_xpc.flags == 0


@pytest.mark.private
def test_lazy_load_dylib_info_modify_offsets(tmp_path: Path):
    bin_path = Path(get_sample("private/MachO/xpcproxy"))
    macho = parse_macho(bin_path).at(0)
    assert macho is not None

    xpc = _get_lazy_loads(macho)[0]
    xpc.pointer_format = 2
    xpc.flag_image_offset = 0x9999
    xpc.chain_start_image_offset = 0

    output = tmp_path / bin_path.name
    macho.write(output)

    new = parse_macho(output).at(0)
    assert new is not None
    check_layout(new)

    new_xpc = _get_lazy_loads(new)[0]
    assert new_xpc.pointer_format == 2
    assert new_xpc.flag_image_offset == 0x9999
    assert new_xpc.chain_start_image_offset == 0
    assert len(list(new_xpc.fixups)) == 0


@pytest.mark.private
def test_lazy_load_dylib_info_layout_check(tmp_path: Path):
    bin_path = Path(get_sample("private/MachO/xpcproxy"))
    macho = parse_macho(bin_path).at(0)
    assert macho is not None

    output = tmp_path / bin_path.name
    macho.write(output)

    def reparse() -> lief.MachO.Binary:
        m = parse_macho(output).at(0)
        assert m is not None
        return m

    check_layout(reparse())

    outbytes = output.read_bytes()
    payload_offset = reparse().lazy_load_dylib_infos[0].data_offset

    def corrupt(field_offset: int, value: int) -> str:
        raw = bytearray(outbytes)
        struct.pack_into("<I", raw, payload_offset + field_offset, value)
        output.write_bytes(raw)
        ok, err = lief.MachO.check_layout(reparse())
        assert not ok
        assert "LAZY_LOAD_DYLIB_INFO" in err
        return err

    # out-of-range loadPathOffset
    assert "loadPathOffset" in corrupt(0, 0xFFFFFFFF)

    # flagImageOffset / chainStartImageOffset beyond the max vm offset
    assert "flagImageOffset" in corrupt(4, 0xFFFFFFFF)
    assert "chainStartImageOffset" in corrupt(12, 0xFFFFFFFF)

    # symbolsCount overflows
    assert "symbolsCount" in corrupt(16, 0xFFFFFFFF)
