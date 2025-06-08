import lief
import pytest
from utils import get_sample
from pathlib import Path
from textwrap import dedent

def test_token_def():
    coff = lief.COFF.parse(get_sample("COFF/psetargv.obj"))
    aux_token: lief.COFF.AuxiliaryCLRToken = coff.symbols[7].auxiliary_symbols[0]
    assert isinstance(aux_token, lief.COFF.AuxiliaryCLRToken)

    assert str(aux_token) == dedent("""\
    AuxiliaryCLRToken {
      Aux Type: 1
      Reserved: 1
      Symbol index: 10
      Symbol: ??0CppInlineNamespaceAttribute@?A0xb81de522@vc.cppcli.attributes@@$$FQE$AAM@PE$AAVString@System@@@Z
      Rgb reserved:
        +---------------------------------------------------------------------+
        | 00 00 00 00 00 00 00 00 00 00 00 00              | ............     |
        +---------------------------------------------------------------------+
    }
    """)
    assert aux_token.aux_type == 1
    assert aux_token.reserved == 1
    assert aux_token.symbol_idx == 10
    assert aux_token.symbol.name == "??0CppInlineNamespaceAttribute@?A0xb81de522@vc.cppcli.attributes@@$$FQE$AAM@PE$AAVString@System@@@Z"
