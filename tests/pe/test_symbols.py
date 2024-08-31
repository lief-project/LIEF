import lief
import pytest
from utils import get_sample

@pytest.mark.skipif(not lief.__extended__, reason="needs LIEF extended")
def test_demangling():
    pe = lief.PE.parse(get_sample("PE/BrowserCore.exe"))
    entry = pe.get_import("msvcp_win.dll").entries[0]
    assert entry.demangled_name == "class std::basic_ostream<char, struct std::char_traits<char>> std::cout"

    pe = lief.PE.parse(get_sample("PE/CloudNotifications.exe"))
    entry = pe.get_delay_import("DUI70.dll").entries[0]
    assert entry.demangled_name == "public: void __cdecl DirectUI::Element::RemoveListener(struct DirectUI::IElementListener *)"

    pe = lief.PE.parse(get_sample("PE/PE64_x86-64_library_libLIEF.dll"))
    entry = pe.get_export().entries[2290]
    assert entry.demangled_name == "typeinfo for LIEF::ELF::SymbolVersionRequirement"

    pe = lief.PE.parse(get_sample("PE/alink.dll"))
    entry = pe.get_export().entries[0]
    assert entry.demangled_name == "class ATL::CComModule & __cdecl GetATLModule(void)"
