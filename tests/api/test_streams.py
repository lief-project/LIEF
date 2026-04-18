import lief
from utils import get_sample


def test_vector_stream_from_file():
    path = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    vs = lief.VectorStream.from_file(path)
    assert isinstance(vs, lief.VectorStream)
    assert vs.size > 0
    content = vs.content
    assert len(content) == vs.size

    # Test slice with offset and size
    sliced = vs.slice(0, 64)
    assert sliced is not None
    assert sliced.size == 64

    # Test slice with only offset
    sliced2 = vs.slice(0)
    assert sliced2 is not None
    assert sliced2.size == vs.size

    # Test slice out of bounds
    sliced3 = vs.slice(vs.size + 100, 10)
    assert sliced3 is None

    # SpanStream content and to_vector
    sliced = vs.slice(0, 128)
    assert sliced is not None
    span_content = sliced.content
    assert len(span_content) == 128

    vec = sliced.to_vector()
    assert vec is not None
    assert vec.size == 128

    # SpanStream slice
    sub = sliced.slice(0, 32)
    assert isinstance(sub, lief.SpanStream)
    assert sub.size == 32


def test_vector_stream_from_file_error():
    vs = lief.VectorStream.from_file("/does/not/exist/at/all")
    assert vs is lief.lief_errors.read_error


def test_file_stream():
    path = get_sample("ELF/ELF64_x86-64_binary_ls.bin")
    fs = lief.FileStream.from_file(path)
    assert isinstance(fs, lief.FileStream)
    assert fs.size > 0
    content = fs.content
    assert len(content) == fs.size


def test_file_stream_error():
    fs = lief.FileStream.from_file("/does/not/exist/at/all")
    assert fs is lief.lief_errors.read_error
