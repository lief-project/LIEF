import lief
import pytest
from utils import parse_pe


@pytest.mark.private
def test_bzimage():
    lief.logging.enable_debug()
    pe = parse_pe("private/bzImage-6.6.8")
    assert pe is not None

    assert len(pe.sections) == 4

    config = lief.PE.Builder.config_t()
    config.force_relocating = True

    pe.write_to_bytes(config)
