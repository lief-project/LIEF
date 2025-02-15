#!python
import lief

def test_simple():
    factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
    text_sec = lief.PE.Section(".text", [
        0xcc, 0xcc
    ])
    factory.add_section(text_sec)
    pe = factory.get()

    text = pe.get_section(".text")

    assert text is not None
    assert list(text.content) == [0xcc, 0xcc]
