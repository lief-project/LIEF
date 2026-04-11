#!python
import lief


def test_simple():
    factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
    assert factory is not None
    text_sec = lief.PE.Section(".text", [0xCC, 0xCC])
    factory.add_section(text_sec)
    pe = factory.get()
    assert pe is not None

    text = pe.get_section(".text")

    assert text is not None
    assert list(text.content) == [0xCC, 0xCC]
