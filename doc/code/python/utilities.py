import lief


def demangle_msvc() -> None:
    # lief-doc: demangle-msvc-start
    lief.demangle("?h@@YAXH@Z")
    # lief-doc: demangle-msvc-end


def demangle_rust() -> None:
    # lief-doc: demangle-rust-start
    lief.demangle("_RNvCskwGfYPst2Cb_3foo16example_function")
    # lief-doc: demangle-rust-end


def demangle_itanium() -> None:
    # lief-doc: demangle-itanium-start
    lief.demangle("_ZTSN3lld13SpecificAllocINS_4coff9TpiSourceEEE")
    # lief-doc: demangle-itanium-end


def demangle_swift() -> None:
    # lief-doc: demangle-swift-start
    lief.demangle("_$s10Foundation4DataV15_RepresentationON")
    # lief-doc: demangle-swift-end


def dump_section() -> None:
    # lief-doc: dump-start
    pe = lief.PE.parse("some.exe")
    assert isinstance(pe, lief.PE.Binary)

    text = pe.get_section(".text")
    assert isinstance(pe, lief.PE.Section)

    print(lief.dump(text.content))
    # lief-doc: dump-end
