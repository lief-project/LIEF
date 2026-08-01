import lief


def embedded() -> None:
    # lief-doc: embedded-start

    elf = lief.ELF.parse("/bin/with_debug")
    if debug_info := elf.debug_info:
        assert isinstance(debug_info, lief.dwarf.DebugInfo)
        print(f"DWARF Debug handler: {debug_info}")
    # lief-doc: embedded-end


def load() -> lief.dwarf.DebugInfo | None:
    # lief-doc: load-start

    dbg: lief.dwarf.DebugInfo | None = lief.dwarf.load("/bin/with_debug")
    dbg: lief.dwarf.DebugInfo | None = lief.dwarf.load("external_dwarf")
    dbg: lief.dwarf.DebugInfo | None = lief.dwarf.load("debug.dwo")
    # lief-doc: load-end
    return dbg


def iterate(dbg: lief.dwarf.DebugInfo) -> None:
    # lief-doc: iterate-start
    dbg: lief.dwarf.DebugInfo

    for compilation_unit in dbg.compilation_units:
        print(compilation_unit.producer)
        for func in compilation_unit.functions:
            print(func.name, func.linkage_name, func.address)

        for var in compilation_unit.variables:
            print(var.name, var.address)

        for ty in compilation_unit.types:
            print(ty.name, ty.size)

    dbg.find_function("_ZNSi4peekEv")
    dbg.find_function("std::basic_istream<char, std::char_traits<char> >::peek()")
    dbg.find_function(0x137A70)

    dbg.find_variable("_ZNSt12out_of_rangeC1EPKc")
    dbg.find_variable("std::out_of_range::out_of_range(char const*)")
    dbg.find_variable(0x2773A0)

    dbg.find_type("my_type_t")
    # lief-doc: iterate-end


def load_external(binary: lief.Binary) -> lief.DebugInfo | None:
    # lief-doc: load-external-start
    binary: lief.Binary

    dbg = binary.load_debug_info("/home/romain/dev/LIEF/some.dwo")
    # lief-doc: load-external-end
    return dbg


def disassemble_external(binary: lief.Binary) -> None:
    # lief-doc: disassemble-start
    binary: lief.Binary

    binary.load_debug_info("/home/romain/dev/LIEF/some.dwo")

    # The location (address/size) of `my_function` is defined in some.dwo
    for inst in binary.disassemble("my_function"):
        print(inst)
    # lief-doc: disassemble-end


def to_decl() -> None:
    # lief-doc: to-decl-start
    dbg = lief.dwarf.load("/bin/with_debug")

    func = dbg.find_function("main")
    print(func.to_decl())

    opt = lief.DeclOpt()
    opt.is_cpp = True
    opt.indentation = 4

    for cu in dbg.compilation_units:
        # Emit the definition of the functions of the compilation unit
        print(cu.to_decl(opt))
    # lief-doc: to-decl-end


def editor_from_binary() -> lief.dwarf.Editor | None:
    # lief-doc: editor-from-binary-start
    pe = lief.PE.parse("demo.exe")
    assert isinstance(pe, lief.PE.Binary)

    editor = lief.dwarf.Editor.from_binary(pe)
    # lief-doc: editor-from-binary-end
    return editor


def editor_create(editor: lief.dwarf.Editor) -> None:
    # lief-doc: editor-create-start
    editor: lief.dwarf.Editor

    unit = editor.create_compilation_unit()
    unit.set_producer("LIEF")

    func = unit.create_function("hello")
    func.set_address(0x123)

    struct_ptr = unit.create_structure("my_struct_t").pointer_to()
    assert isinstance(struct_ptr, lief.dwarf.editor.PointerType)

    func.set_return_type(struct_ptr)

    var = func.create_stack_variable("local_var")
    var.set_stack_offset(8)

    editor.write("/tmp/out.debug")
    # lief-doc: editor-create-end
