import lief
from utils import parse_pe


def test_simple():
    """
    Referential test on a simple case
    This test aims at checking we cover correctly a regular binary
    """
    binary = parse_pe("PE/test.delay.exe")

    assert binary.has_delay_imports
    assert len(binary.delay_imports) == 2
    assert binary.get_delay_import("USER32.dll") is not None
    assert binary.has_delay_import("USER32.dll")

    # Check that took care of updating the abstract layer
    assert len(binary.imported_functions) == 87
    assert len(binary.libraries) == 3

    # Now check in depth the delay imports
    shlwapi = binary.delay_imports[0]
    assert shlwapi.name == "SHLWAPI.dll"
    assert shlwapi.attribute == 1
    assert shlwapi.handle == 0x29DC8
    assert shlwapi.iat == 0x25D30
    assert shlwapi.names_table == 0x23F48
    assert shlwapi.biat == 0x23F80
    assert shlwapi.uiat == 0
    assert shlwapi.timestamp == 0
    assert len(shlwapi.entries) == 1

    strstra = shlwapi.entries[0]

    assert strstra.name == "StrStrA"
    assert strstra.value == 0x00025D30
    assert strstra.iat_value == 0x140001983
    assert strstra.data == 0x23F68
    assert strstra.hint == 0x14D

    user32 = binary.delay_imports[1]
    assert user32.name == "USER32.dll"
    assert user32.attribute == 1
    assert user32.handle == 0x29DD0
    assert user32.iat == 0x25D40
    assert user32.names_table == 0x23F58
    assert user32.biat == 0x23F90
    assert user32.uiat == 0
    assert user32.timestamp == 0
    assert len(user32.entries) == 1
    assert user32.copy() == user32

    messageboxa = user32.entries[0]
    assert messageboxa.copy() == messageboxa
    assert messageboxa.copy().copy() != user32

    assert messageboxa.ordinal == 0x3F72
    assert messageboxa.name == "MessageBoxA"
    assert messageboxa.value == 0x25D40
    assert messageboxa.iat_value == 0x140001A08
    assert messageboxa.data == 0x23F72
    assert messageboxa.hint == 0x285
    lief.logging.info(messageboxa)


def test_cmd():
    """
    Test on cmd.exe
    """
    binary = parse_pe("PE/PE64_x86-64_binary_cmd.exe")

    assert binary.has_delay_imports
    assert len(binary.delay_imports) == 4

    assert len(binary.imported_functions) == 247
    assert len(binary.libraries) == 8

    shell32 = binary.get_delay_import("SHELL32.dll")
    assert shell32 is not None
    assert shell32.name == "SHELL32.dll"
    assert shell32.attribute == 1
    assert shell32.handle == 0x2E2E8
    assert shell32.iat == 0x2E078
    assert shell32.names_table == 0x2A5A0
    assert shell32.biat == 0
    assert shell32.uiat == 0
    assert shell32.timestamp == 0
    assert len(shell32.entries) == 2

    SHChangeNotify = shell32.entries[0]

    assert SHChangeNotify.name == "SHChangeNotify"
    assert SHChangeNotify.value == 0x0002E078
    assert SHChangeNotify.iat_value == 0x4AD27BC8
    assert SHChangeNotify.data == 0x2A6EE
    assert SHChangeNotify.hint == 0

    ShellExecuteExW = shell32.entries[1]

    assert ShellExecuteExW.name == "ShellExecuteExW"
    assert ShellExecuteExW.value == 0x0002E080
    assert ShellExecuteExW.iat_value == 0x4AD155A0
    assert ShellExecuteExW.data == 0x2A700
    assert ShellExecuteExW.hint == 0
