import lief

CPA = lief.MachO.ChainedPointerAnalysis
FMT = lief.MachO.DYLD_CHAINED_PTR_FORMAT


def test_value_and_size():
    cpa = CPA.from_value(0x1234567890ABCDEF, 8)
    assert cpa is not None
    assert cpa.value == 0x1234567890ABCDEF
    assert cpa.size == 8


def test_get_as_ptr64_rebase():
    cpa = CPA.from_value(0x1234567890ABCDEF, 8)
    assert cpa is not None
    ptr = cpa.get_as(FMT.PTR_64)
    assert isinstance(ptr, CPA.dyld_chained_ptr_64_rebase_t)
    assert ptr.bind is False
    assert ptr.high8 == 103
    assert ptr.reserved == 69
    assert ptr.next == 582
    assert ptr.target == 36786916847
    assert ptr.unpack_target == 36786916847


def test_get_as_ptr64_bind():
    cpa = CPA.from_value(0x8000000000000001, 8)
    assert cpa is not None
    ptr = cpa.get_as(FMT.PTR_64)
    assert isinstance(ptr, CPA.dyld_chained_ptr_64_bind_t)
    assert ptr.bind is True
    assert ptr.ordinal == 1
    assert ptr.addend == 0
    assert ptr.reserved == 0
    assert ptr.next == 0


def test_get_as_arm64e_auth_rebase():
    cpa = CPA.from_value(0x8000000000000001, 8)
    assert cpa is not None
    ptr = cpa.get_as(FMT.PTR_ARM64E)
    assert isinstance(ptr, CPA.dyld_chained_ptr_arm64e_auth_rebase_t)
    assert ptr.auth == 1
    assert ptr.bind is False
    assert ptr.target == 1


def test_get_as_ptr32_bind():
    cpa = CPA.from_value(0x00000000DEADBEEF, 4)
    assert cpa is not None
    ptr = cpa.get_as(FMT.PTR_32)
    assert isinstance(ptr, CPA.dyld_chained_ptr_32_bind_t)
    assert ptr.bind is True
    assert ptr.ordinal == 900847
    assert ptr.addend == 42
    assert ptr.next == 23


def test_get_as_zero_is_rebase():
    cpa = CPA.from_value(0, 8)
    assert cpa is not None
    ptr = cpa.get_as(FMT.PTR_64)
    assert isinstance(ptr, CPA.dyld_chained_ptr_64_rebase_t)
    assert ptr.target == 0
    assert ptr.next == 0


def test_get_as_unknown_format_returns_raw_int():
    cpa = CPA.from_value(0xFF, 8)
    assert cpa is not None
    ptr = cpa.get_as(FMT.NONE)
    assert isinstance(ptr, int)
    assert ptr == 0


def test_direct_getter_decodes_bitfields():
    cpa = CPA.from_value(0x1234567890ABCDEF, 8)
    assert cpa is not None
    rebase = cpa.dyld_chained_ptr_arm64e_rebase
    assert rebase.auth is False
    assert rebase.bind is False
    assert rebase.high8 == 138
    assert rebase.next == 582
    assert rebase.target == 7114893020655
