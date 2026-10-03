import gc
from typing import cast

import lief
import pytest
from utils import get_sample, parse_elf

if not lief.__extended__:
    pytest.skip("skipping: extended version only", allow_module_level=True)

Location = lief.dwarf.Location
CompositeLocation = lief.dwarf.CompositeLocation
Piece = lief.dwarf.CompositeLocation.Piece


def _load_pieces() -> lief.dwarf.DebugInfo:
    dbg = lief.dwarf.load(get_sample("DWARF/main_DW_OP_piece.elf"))
    assert dbg is not None
    return dbg


def _function(dbg: lief.dwarf.DebugInfo, name: str) -> lief.dwarf.Function:
    func = dbg.find_function(name)
    assert func is not None
    return func


def _param(dbg: lief.dwarf.DebugInfo, name: str) -> lief.dwarf.Parameter:
    params = _function(dbg, name).parameters
    assert len(params) == 1
    assert params[0] is not None
    return params[0]


def _variable(func: lief.dwarf.Function, name: str) -> lief.dwarf.Variable:
    for var in func.variables:
        if var is not None and var.name == name:
            return var
    raise AssertionError(f"variable {name} not found")


def _pieces(loc: lief.dwarf.Location | None) -> list[Piece]:
    assert isinstance(loc, CompositeLocation)
    assert loc.type == Location.Type.COMPOSITE
    return loc.pieces


def _reg(piece: Piece) -> int:
    loc = piece.location
    assert isinstance(loc, lief.dwarf.RegisterLoc)
    return loc.id


def test_parameter_register_pieces():
    dbg = _load_pieces()
    func = _function(dbg, "process_pair")
    param = _param(dbg, "process_pair")

    pieces = _pieces(param.location)
    assert len(pieces) == 2
    assert [_reg(p) for p in pieces] == [5, 4]  # rdi, rsi
    assert [p.bit_size for p in pieces] == [64, 64]
    assert [p.bit_offset for p in pieces] == [0, 64]
    assert all(p.kind == Piece.KIND.BYTE for p in pieces)
    assert all(p.source_bit_offset is None for p in pieces)

    address = func.address
    assert address == 0x1120
    assert param.location_at(address) is not None
    # The range is half-open
    assert param.location_at(address + func.size) is None

    entries = param.locations
    assert len(entries) == 1
    entry = entries[0]
    assert entry.range is not None
    assert (entry.range.low, entry.range.high) == (0x1120, 0x1127)
    assert str(entry) == (
        "[0x1120, 0x1127): pieces {bits [0, 64): register 5 (8 bytes), "
        "bits [64, 128): register 4 (8 bytes)}"
    )
    assert str(entry.location) == str(entry).split(": ", 1)[1]

    # A 128-bit integer is split in the same registers
    assert [_reg(p) for p in _pieces(_param(dbg, "process_i128").location)] == [5, 4]


def test_parameter_location_list():
    dbg = _load_pieces()
    param = _param(dbg, "process_mixed")

    # The location changes with the program counter
    assert param.location is None

    entries = param.locations
    assert len(entries) == 2
    assert entries[0].range is not None
    assert (entries[0].range.low, entries[0].range.high) == (0x1130, 0x1136)

    first = _pieces(entries[0].location)
    assert len(first) == 2
    assert [_reg(p) for p in first] == [5, 4]
    assert first[1].bit_size == 32

    second = _pieces(entries[1].location)
    assert len(second) == 3
    assert isinstance(second[1].location, lief.dwarf.UnavailableLoc)
    assert second[1].location.type == Location.Type.UNAVAILABLE
    assert second[2].bit_offset == 96

    expr = second[2].location
    assert isinstance(expr, lief.dwarf.ExpressionLoc)
    assert expr.type == Location.Type.EXPRESSION
    assert "DW_OP_convert" in expr.description
    assert "DW_OP_stack_value" in expr.description
    assert isinstance(expr.expression, bytes)
    assert expr.expression[0] == 0x74  # DW_OP_breg4 (rsi)

    # [0x1130, 0x1136) is half-open
    assert len(_pieces(param.location_at(0x1135))) == 2
    assert len(_pieces(param.location_at(0x1136))) == 3
    assert param.location_at(0x2000) is None


def test_local_variables():
    dbg = _load_pieces()
    main = _function(dbg, "main")

    pair = _variable(main, "pair")
    entries = pair.locations
    assert len(entries) == 3
    assert [len(_pieces(e.location)) for e in entries] == [1, 2, 1]
    assert pair.location is None
    assert pair.address is None
    assert not pair.is_stack_based
    assert pair.location_at(0x1157) is None
    assert pair.location_at(0x11A0) is None

    mixed = _pieces(_variable(main, "mixed").location_at(0x117C))
    assert [_reg(p) for p in mixed] == [5, 0, 4]
    assert (mixed[2].bit_offset, mixed[2].bit_size) == (96, 32)

    large = _pieces(_variable(main, "large").location_at(0x1192))
    assert len(large) == 2
    assert isinstance(large[0].location, lief.dwarf.UnavailableLoc)
    assert large[0].bit_size == 64
    assert _reg(large[1]) == 3

    # A location list with a single entry is also the unique location
    r1 = _variable(main, "r1").location
    assert isinstance(r1, lief.dwarf.RegisterLoc)
    assert r1.type == Location.Type.REGISTER
    assert r1.id == 14
    assert str(r1) == "register 14"

    # Parameter's location list with an entry value
    argc = main.parameters[0]
    assert argc is not None
    assert argc.name == "argc"

    argc_entries = argc.locations
    assert len(argc_entries) == 2
    assert isinstance(argc_entries[0].location, lief.dwarf.RegisterLoc)

    entry_value = argc_entries[1].location
    assert isinstance(entry_value, lief.dwarf.ExpressionLoc)
    assert "DW_OP_entry_value" in entry_value.description


def test_to_string_matches_to_decl():
    dbg = _load_pieces()
    main = _function(dbg, "main")
    opt = lief.DeclOpt()
    opt.is_cpp = True
    decl = main.to_decl(opt)
    for entry in _variable(main, "large").locations:
        assert str(entry) in decl


def test_memory_locations():
    elf = parse_elf(get_sample("DWARF/vars_1.elf"))
    dbg = cast(lief.dwarf.DebugInfo, elf.debug_info)
    assert isinstance(dbg, lief.dwarf.DebugInfo)

    g_map = dbg.find_variable("g_map")
    assert g_map is not None

    loc = g_map.location
    assert isinstance(loc, lief.dwarf.AddressLoc)
    assert loc.type == Location.Type.ADDRESS
    assert loc.address == 0x40E0
    assert str(loc) == "memory 0x40e0"

    entries = g_map.locations
    assert len(entries) == 1
    assert entries[0].range is None
    assert entries[0].section_index is None
    assert str(entries[0]) == "default: memory 0x40e0"

    # An entry without range is valid everywhere
    assert isinstance(g_map.location_at(0), lief.dwarf.AddressLoc)

    main = dbg.find_function("main")
    assert main is not None

    local = _variable(main, "local_var_1")
    assert local.is_stack_based

    frame = local.location
    assert isinstance(frame, lief.dwarf.FrameBaseLoc)
    assert frame.type == Location.Type.FRAME_BASE
    assert frame.offset == -72
    assert frame.offset == local.address
    assert str(frame) == "memory [frame base -72]"


@pytest.mark.linux
def test_lifetime():
    """
    Locations are self-contained: they remain valid once the debug info is
    released.
    """
    dbg = _load_pieces()
    composite = _param(dbg, "process_pair").location
    entries = _param(dbg, "process_mixed").locations
    del dbg
    gc.collect()

    pieces = _pieces(composite)
    del composite
    gc.collect()
    assert [_reg(p) for p in pieces] == [5, 4]

    inner = _pieces(entries[1].location)[2].location
    del entries
    gc.collect()
    assert isinstance(inner, lief.dwarf.ExpressionLoc)
    assert "DW_OP_stack_value" in inner.description
