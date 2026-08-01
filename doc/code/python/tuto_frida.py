import lief


def inject_gadget() -> None:
    # lief-doc: inject-start

    libnative = lief.parse("libnative.so")
    assert isinstance(libnative, lief.ELF.Binary)

    libnative.add_library("libgadget.so")  # Injection!
    libnative.write("libnative.so")
    # lief-doc: inject-end
