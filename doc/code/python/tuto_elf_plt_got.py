import lief


def inject_hook() -> None:
    # lief-doc: inject-start

    crackme = lief.parse("crackme.bin")
    assert isinstance(crackme, lief.ELF.Binary)

    hook = lief.parse("hook")
    assert isinstance(hook, lief.ELF.Binary)

    segment_added = crackme.add(hook.segments[0])
    # lief-doc: inject-end
    _ = segment_added


def compute_hook_address(hook: lief.ELF.Binary, segment_added: lief.ELF.Segment) -> int:
    # lief-doc: hook-address-start
    hook: lief.ELF.Binary
    segment_added: lief.ELF.Segment

    my_memcmp = hook.get_symbol("my_memcmp")
    assert my_memcmp is not None

    my_memcmp_addr = segment_added.virtual_address + my_memcmp.value
    # lief-doc: hook-address-end
    return my_memcmp_addr


def patch_got(crackme: lief.ELF.Binary, my_memcmp_addr: int) -> None:
    # lief-doc: patch-got-start
    crackme.patch_pltgot("memcmp", my_memcmp_addr)
    # lief-doc: patch-got-end


def rebuild(crackme: lief.ELF.Binary) -> None:
    # lief-doc: rebuild-start
    crackme.write("crackme.hooked")
    # lief-doc: rebuild-end
