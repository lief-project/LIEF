import lief


def modify_callbacks(pe: lief.PE.Binary) -> None:
    # lief-doc: modify-callbacks-start
    pe: lief.PE.Binary

    tls = pe.tls
    assert isinstance(tls, lief.PE.TLS)

    callbacks: list[int] = tls.callbacks

    # Remove the last entry
    callbacks.pop()

    # Add an address
    callbacks.append(0x140001010)

    tls.callbacks = callbacks

    pe.write("tls_modified.exe")
    # lief-doc: modify-callbacks-end


def create_tls() -> lief.PE.TLS:
    # lief-doc: create-tls-start
    tls = lief.PE.TLS()

    tls.callbacks = [
        0x140001000,
        0x140001010,
    ]
    # lief-doc: create-tls-end
    return tls


def add_tls(pe: lief.PE.Binary) -> None:
    tls = create_tls()
    # lief-doc: add-tls-start
    pe.tls = tls  # `tls` defined previously

    pe.write("tls_demo.exe")
    # lief-doc: add-tls-end
