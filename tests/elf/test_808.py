import lief
from utils import get_sample


def test_core_offset_0():
    file = get_sample("ELF/ELF_Core_issue_808.core")
    core = lief.ELF.parse(file)
    assert core is not None
    assert len(core.notes) == 7
