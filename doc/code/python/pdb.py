import lief


def load_pdb(pe: lief.PE.Binary) -> lief.pdb.DebugInfo | None:
    # lief-doc: load-start
    pe: lief.PE.Binary

    if (debug_info := pe.debug_info) is not None:
        assert isinstance(debug_info, lief.pdb.DebugInfo)
        print(f"PDB Debug handler: {debug_info}")

    # Or you can load the PDB directly:
    pdb = lief.pdb.load("some.pdb")
    # lief-doc: load-end
    return pdb


def load_ext(binary: lief.Binary) -> lief.DebugInfo | None:
    # lief-doc: load-ext-start
    binary: lief.Binary

    dbg = binary.load_debug_info(r"C:\Users\romain\LIEF.pdb")
    # lief-doc: load-ext-end
    return dbg


def disassemble(binary: lief.Binary) -> lief.DebugInfo | None:
    # lief-doc: disassemble-start
    binary: lief.Binary

    dbg = binary.load_debug_info(r"C:\Users\romain\LIEF.pdb")

    # The location (address/size) of `my_function` is defined in LIEF.pdb
    for inst in binary.disassemble("my_function"):
        print(inst)
    # lief-doc: disassemble-end
    return dbg


def to_decl(pdb: lief.pdb.DebugInfo) -> None:
    # lief-doc: to-decl-start
    pdb: lief.pdb.DebugInfo

    opt = lief.DeclOpt()
    opt.is_cpp = True

    for ty in pdb.types:
        print(ty.to_decl(opt))

    for cu in pdb.compilation_units:
        # Emit the definition of the functions of the compilation unit
        print(cu.to_decl(opt))

        for func in cu.functions:
            print(func.to_decl(opt))
    # lief-doc: to-decl-end


def explore(pdb: lief.pdb.DebugInfo) -> None:
    # lief-doc: explore-start
    pdb: lief.pdb.DebugInfo

    print(f"arg={pdb.age}, guid={pdb.guid}")

    for sym in pdb.public_symbols:
        print(f"name={sym.name}, section={sym.section_name}, RVA={sym.RVA}")

    for ty in pdb.types:
        if isinstance(ty, lief.pdb.types.Class):
            print(f"Class[name]={ty.name}")

    for cu in pdb.compilation_units:
        print(f"module={cu.module_name}")
        for src in cu.sources:
            print(f"  - {src}")

        for func in cu.functions:
            print(
                f"name={func.name}, section={func.section_name}, RVA={func.RVA}, code_size={func.code_size}"
            )
    # lief-doc: explore-end
