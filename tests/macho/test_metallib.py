import lief
from utils import get_sample

def test_binary_metallib():
    fat = lief.MachO.parse(get_sample("MachO/binary.metallib"))
    assert len(fat) == 15
