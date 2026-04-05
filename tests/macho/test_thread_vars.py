import lief
import pytest
from utils import get_sample

def test_thread_variables():
    macho = lief.MachO.parse(get_sample("MachO/lief-dwarf-plugin-darwin-arm64.dylib")).at(0)
    thread_vars = macho.get_section("__thread_vars")
    assert thread_vars is not None
    assert isinstance(thread_vars, lief.MachO.ThreadLocalVariables)
    assert thread_vars.nb_thunks == 2

    assert thread_vars.type == lief.MachO.Section.TYPE.THREAD_LOCAL_VARIABLES
    assert thread_vars.name == "__thread_vars"
    assert thread_vars.segment_name == "__DATA"

    t0 = thread_vars.get(0)
    assert t0 is not None
    assert t0.func == 0
    assert t0.key == 0
    assert t0.offset == 0

    t1 = thread_vars.get(1)
    assert t1 is not None
    assert t1.offset == 0x18

    assert thread_vars.get(99) is None

    assert "offset=0x000018" in str(t1)

    # Test the thunks iterator
    thunks = list(thread_vars.thunks)
    assert len(thunks) == 2
    assert thunks[0].offset == 0
    assert thunks[1].offset == 0x18

    # Test operator[] (__getitem__)
    assert thread_vars[0] is not None
    assert thread_vars[0].func == 0
    assert thread_vars[0].offset == 0
    assert thread_vars[1].offset == 0x18
    assert thread_vars[99] is None

    # Test set() and __setitem__
    original_t0 = thread_vars.get(0)
    new_thunk = lief.MachO.ThreadLocalVariables.Thunk(0xAABB, 0xCCDD, 0xEEFF)
    thread_vars.set(0, new_thunk)
    modified = thread_vars.get(0)
    assert modified.func == 0xAABB
    assert modified.key == 0xCCDD
    assert modified.offset == 0xEEFF

    thread_vars[0] = lief.MachO.ThreadLocalVariables.Thunk(
        original_t0.func, original_t0.key, original_t0.offset
    )
    restored = thread_vars[0]
    assert restored.func == original_t0.func
    assert restored.key == original_t0.key
    assert restored.offset == original_t0.offset

    # Test Thunk construction and mutable fields
    t = lief.MachO.ThreadLocalVariables.Thunk()
    assert t.func == 0 and t.key == 0 and t.offset == 0

    t.func = 0x1000
    t.key = 0x2000
    t.offset = 0x3000
    assert t.func == 0x1000
    assert t.key == 0x2000
    assert t.offset == 0x3000

@pytest.mark.private
def test_check_layout():
    macho = lief.MachO.parse(get_sample("private/MachO/thread_variables.dylib")).at(0)
    assert macho is not None
    ok, msg = lief.MachO.check_layout(macho)
    assert not ok
    assert msg == 'malformed thread-local, offset=0x9000000000 is larger than total size=0x000090\n'
