import lief
import pytest
from utils import parse_macho


@pytest.mark.private
def test_basic_info():
    fat = parse_macho("private/MachO/kernelcache.release.iPhone17.5")
    assert len(fat) == 1

    macho = fat.at(0)
    assert macho is not None

    assert len(macho.filesets) == 293

    corecrypto = macho.commands[301]
    assert isinstance(corecrypto, lief.MachO.FilesetCommand)

    assert corecrypto.name == "com.apple.kec.corecrypto"
    assert corecrypto.virtual_address == 0xFFFFFFF007AC3820
    assert corecrypto.file_offset == 0xABF820

    corecrypto_macho = corecrypto.binary

    assert corecrypto_macho is not None
    assert corecrypto_macho.fileset_name == "com.apple.kec.corecrypto"
    assert corecrypto_macho.fileset_addr == 0xFFFFFFF007AC3820
