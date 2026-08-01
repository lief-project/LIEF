import lief


def show_relocations(app: lief.MachO.Binary) -> None:
    # lief-doc: relocations-start
    app: lief.MachO.Binary

    for relocation in app.relocations:
        print(relocation)
    # lief-doc: relocations-end


def show_export_info(app: lief.MachO.Binary) -> None:
    # lief-doc: export-info-start
    app: lief.MachO.Binary

    for s in app.symbols:
        if s.has_export_info:
            print(s.export_info)
    # lief-doc: export-info-end


def remove_signature(ssh: lief.MachO.Binary) -> None:
    # lief-doc: remove-signature-start
    ssh: lief.MachO.Binary

    ssh.remove_signature()

    ssh.write("ssh.nosigned")
    # lief-doc: remove-signature-end


def add_library(clang: lief.MachO.Binary) -> None:
    # lief-doc: add-library-start
    clang: lief.MachO.Binary

    clang.add_library("/Users/romain/libexample.dylib")

    clang.write("/tmp/clang.new")
    # lief-doc: add-library-end


def add_section(
    app: lief.MachO.Binary, raw_shell: list[int]
) -> lief.MachO.Section | None:
    # lief-doc: add-section-start
    app: lief.MachO.Binary
    raw_shell: list[int]

    section = lief.MachO.Section.create("__shell", raw_shell)
    assert isinstance(section, lief.MachO.Section)

    section.alignment = 2
    section += lief.MachO.Section.FLAGS.SOME_INSTRUCTIONS
    section += lief.MachO.Section.FLAGS.PURE_INSTRUCTIONS

    section = app.add_section(section)
    print(section)
    # lief-doc: add-section-end
    return section


def remove_signature_and_write(app: lief.MachO.Binary) -> None:
    # lief-doc: remove-sig-write-start
    app: lief.MachO.Binary

    app.remove_signature()
    app.write("./id.modified")
    # lief-doc: remove-sig-write-end


def show_rebase_opcodes() -> None:
    # lief-doc: rebase-opcodes-start
    app = lief.parse("MachO64_x86-64_binary_id.bin")
    print(app.dyld_info.show_rebases_opcodes)
    # lief-doc: rebase-opcodes-end


def show_bind_opcodes(app: lief.MachO.Binary) -> None:
    # lief-doc: bind-opcodes-start
    app: lief.MachO.Binary

    print(app.dyld_info.show_bind_opcodes)
    # lief-doc: bind-opcodes-end


def show_export_trie() -> None:
    # lief-doc: export-trie-start
    app = lief.parse("FAT_MachO_x86_x86-64_library_libdyld.dylib")
    print(app.dyld_info.show_export_trie)
    # lief-doc: export-trie-end


def set_entrypoint(app: lief.MachO.Binary, section: lief.MachO.Section) -> None:
    # lief-doc: set-entrypoint-start
    app: lief.MachO.Binary
    section: lief.MachO.Section

    __TEXT = app.get_segment("__TEXT")
    assert __TEXT is not None

    main = app.main_command
    assert main is not None

    main.entrypoint = section.virtual_address - __TEXT.virtual_address
    # lief-doc: set-entrypoint-end
