import lief


def list_segments(core: lief.ELF.Binary) -> None:
    # lief-doc: segments-start
    core: lief.ELF.Binary

    segments = core.segments
    print(f"Number of segments {len(segments)}")

    for segment in segments:
        print(hex(segment.virtual_address))
    # lief-doc: segments-end


def corefile_check(binary: lief.ELF.Binary) -> None:
    # lief-doc: corefile-check-start
    binary: lief.ELF.Binary

    for note in binary.notes:
        if isinstance(note, lief.ELF.CoreFile):
            print("This is a CoreFile note")
    # lief-doc: corefile-check-end


def iter_files(nt_core_file: lief.ELF.CoreFile) -> None:
    # lief-doc: iter-files-start
    nt_core_file: lief.ELF.CoreFile

    for file_entry in nt_core_file:
        print(file_entry)
    # lief-doc: iter-files-end


def registers(core: lief.ELF.Binary) -> None:
    # lief-doc: registers-start
    core: lief.ELF.Binary

    for note in core.notes:
        if not isinstance(note, lief.ELF.CorePrStatus):
            continue

        # Both are equivalent
        print(note.pc)
        reg_values = note.register_values
        print(reg_values[lief.ELF.CorePrStatus.Registers.AARCH64.PC.value])
    # lief-doc: registers-end


def set_register(core: lief.ELF.Binary) -> None:
    # lief-doc: set-register-start
    core: lief.ELF.Binary

    prstatus = core.get(lief.ELF.Note.TYPE.CORE_PRSTATUS)
    assert isinstance(prstatus, lief.ELF.CorePrStatus)

    prstatus.set(lief.ELF.CorePrStatus.Registers.AARCH64.PC, 0xDEADC0DE)

    core.write("/tmp/new.core")
    # lief-doc: set-register-end


def parse_coredump() -> None:
    # lief-doc: parse-core-start

    core = lief.parse("ELF64_AArch64_core_hello.core")
    # lief-doc: parse-core-end
    _ = core


def get_corefile(core: lief.ELF.Binary) -> lief.ELF.Note | None:
    # lief-doc: get-corefile-start
    core: lief.ELF.Binary

    nt_core_file = core.get(lief.ELF.Note.TYPE.CORE_FILE)
    # lief-doc: get-corefile-end
    return nt_core_file
