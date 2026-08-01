import lief


def hooking(libm: lief.ELF.Binary, hook: lief.ELF.Binary) -> None:
    # lief-doc: inject-start
    libm: lief.ELF.Binary
    hook: lief.ELF.Binary

    exp_symbol = libm.get_symbol("exp")
    hook_symbol = hook.get_symbol("hook")
    assert hook_symbol is not None

    code_segment = hook.segment_from_virtual_address(hook_symbol.value)
    assert code_segment is not None

    segment_added = libm.add(code_segment)
    # lief-doc: inject-end
    assert exp_symbol is not None
    assert segment_added is not None

    # lief-doc: update-start
    new_address = (
        segment_added.virtual_address + hook_symbol.value - code_segment.virtual_address
    )
    exp_symbol.value = new_address
    exp_symbol.type = lief.ELF.Symbol.TYPE.FUNC  # it might have been GNU_IFUNC
    # lief-doc: update-end

    # lief-doc: write-start
    libm.write("libm.so.6")
    # lief-doc: write-end
