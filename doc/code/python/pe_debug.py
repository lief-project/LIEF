import lief


def change_name(pe: lief.PE.Binary) -> None:
    # lief-doc: change-name-start
    pe: lief.PE.Binary

    assert isinstance(pe.codeview_pdb, lief.PE.CodeViewPDB)
    pe.codeview_pdb.filename = r"C:\A\B\C\path.pdb"

    pe.write("out.dll")
    # lief-doc: change-name-end


def remove(pe: lief.PE.Binary) -> None:
    # lief-doc: remove-start
    # Remove a single CodeViewPDB entry
    assert pe.codeview_pdb is not None
    pe.remove_debug(pe.codeview_pdb)

    # Remove all entries
    pe.clear_debug()

    pe.write("out.dll")
    # lief-doc: remove-end


def add(pe: lief.PE.Binary) -> None:
    # lief-doc: add-start
    cv = lief.PE.CodeViewPDB("MyCustom.pdb")

    pe.add_debug_info(cv)

    pe.write("out.dll")
    # lief-doc: add-end
