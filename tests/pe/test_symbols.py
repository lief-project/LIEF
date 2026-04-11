import lief
import pytest
from utils import parse_pe


@pytest.mark.skipif(not lief.__extended__, reason="needs LIEF extended")
def test_demangling():
    pe = parse_pe("PE/BrowserCore.exe")
    imp = pe.get_import("msvcp_win.dll")
    assert imp is not None
    entry = imp.entries[0]
    assert (
        entry.demangled_name
        == "class std::basic_ostream<char, struct std::char_traits<char>> std::cout"
    )

    pe = parse_pe("PE/CloudNotifications.exe")
    delay_imp = pe.get_delay_import("DUI70.dll")
    assert delay_imp is not None
    entry = delay_imp.entries[0]
    assert (
        entry.demangled_name
        == "public: void __cdecl DirectUI::Element::RemoveListener(struct DirectUI::IElementListener *)"
    )

    pe = parse_pe("PE/PE64_x86-64_library_libLIEF.dll")
    export = pe.get_export()
    assert export is not None
    entry = export.entries[2290]
    assert entry.demangled_name == "typeinfo for LIEF::ELF::SymbolVersionRequirement"

    pe = parse_pe("PE/alink.dll")
    export = pe.get_export()
    assert export is not None
    entry = export.entries[0]
    assert entry.demangled_name == "class ATL::CComModule & __cdecl GetATLModule(void)"
