import lief

from utils import get_sample

def test_issue_1215():
    assert not lief.is_macho(get_sample("MachO/DmgInfoGenerator.class"))
