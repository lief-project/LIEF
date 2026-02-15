import lief
import pytest

from utils import has_private_samples, get_sample


@pytest.mark.skipif(condition=not has_private_samples(), reason="needs private samples")
def test_bzimage():
    lief.logging.enable_debug()
    pe = lief.PE.parse(get_sample("private/bzImage-6.6.8"))
    assert pe is not None

    assert len(pe.sections) == 4

    config = lief.PE.Builder.config_t()
    config.force_relocating = True

    pe.write_to_bytes(config)
