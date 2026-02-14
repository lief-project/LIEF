import lief
import pytest

from utils import has_private_samples, get_sample

@pytest.mark.skipif(not has_private_samples(), reason="needs private samples")
def test_basic_info():
    fat = lief.MachO.parse(get_sample("private/MachO/kernelcache.release.iPhone17.5"))
    assert len(fat) == 1

    macho = fat.at(0)

    assert len(macho.filesets) == 293

    corecrypto = macho.commands[301]
    assert isinstance(corecrypto, lief.MachO.FilesetCommand)

    assert corecrypto.name == "com.apple.kec.corecrypto"
    assert corecrypto.virtual_address == 0xfffffff007ac3820
    assert corecrypto.file_offset == 0xabf820

    corecrypto_macho = corecrypto.binary

    assert corecrypto_macho is not None
    assert corecrypto_macho.fileset_name == "com.apple.kec.corecrypto"
    assert corecrypto_macho.fileset_addr == 0xfffffff007ac3820
