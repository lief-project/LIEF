import lief


def oat_symbols() -> None:
    # lief-doc: oat-symbols-start
    oat = lief.OAT.parse("SomeOAT")
    assert oat is not None
    for s in oat.dynamic_symbols:
        print(s)
    # lief-doc: oat-symbols-end


def oat_extract_dex(oat: lief.OAT.Binary) -> None:
    # lief-doc: oat-extract-dex-start
    oat: lief.OAT.Binary

    dex = oat.dex_files[0]
    dex.save("/tmp/classes.dex")
    # lief-doc: oat-extract-dex-end


def dex_source_files(dex: lief.DEX.File) -> None:
    # lief-doc: dex-source-files-start
    dex: lief.DEX.File

    for cls in dex.classes:
        if cls.source_filename:
            print(cls)
    # lief-doc: dex-source-files-end


def dex_strings(dex: lief.DEX.File) -> None:
    # lief-doc: dex-strings-start
    dex: lief.DEX.File

    for s in dex.strings:
        if "http" in s:
            print(s)
    # lief-doc: dex-strings-end


def dex_deobfuscate(dex: lief.DEX.File) -> None:
    # lief-doc: dex-deobfuscate-start
    dex: lief.DEX.File

    for cls in dex.classes:
        if cls.source_filename:
            print(cls.pretty_name + ": ---> " + cls.source_filename)
    # lief-doc: dex-deobfuscate-end


def art_header() -> None:
    # lief-doc: art-header-start
    art = lief.ART.parse("boot.art")
    assert isinstance(art, lief.ART.File)

    print(art.header)
    # lief-doc: art-header-end
