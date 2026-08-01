import lief


def disassemble(elf: lief.ELF.Binary) -> None:
    # lief-doc: disassemble-start
    elf: lief.ELF.Binary

    for inst in elf.disassemble(0x400120):
        print(inst)
    # lief-doc: disassemble-end


def check_opcode(
    inst: lief.assembly.Instruction,
) -> "lief.assembly.riscv.OPCODE | None":
    # lief-doc: downcast-start
    inst: lief.assembly.Instruction

    match inst:
        case lief.assembly.riscv.Instruction():
            opcode: lief.assembly.riscv.OPCODE = inst.opcode
            # lief-doc: downcast-end
            return opcode
    return None


def dsc_disassemble(dyld_cache: lief.dsc.DyldSharedCache) -> None:
    # lief-doc: dsc-disassemble-start
    dyld_cache: lief.dsc.DyldSharedCache

    for inst in dyld_cache.disassemble(0x1886F4A44):
        print(inst)
    # lief-doc: dsc-disassemble-end


def operands_aarch64(macho: lief.MachO.Binary) -> None:
    # lief-doc: operands-aarch64-start
    macho: lief.MachO.Binary

    for inst in macho.disassemble(0x400120):
        print(inst)
        # Check inst properties
        if inst.is_branch:
            print(f"Resolved: {inst.branch_target}")

        for idx, operand in enumerate(inst.operands):
            match operand:
                case lief.assembly.aarch64.operands.Register():
                    print(f"op[{idx}]: REG - {operand.value}")
                case lief.assembly.aarch64.operands.Memory():
                    print(f"op[{idx}]: MEM - {operand.base}")
                case lief.assembly.aarch64.operands.PCRelative():
                    print(f"op[{idx}]: PCR - {operand.value}")
                case lief.assembly.aarch64.operands.Immediate():
                    print(f"op[{idx}]: IMM - {operand.value}")
    # lief-doc: operands-aarch64-end


def operands_x86(elf: lief.ELF.Binary) -> None:
    # lief-doc: operands-x86-start
    elf: lief.ELF.Binary

    for inst in elf.disassemble(0x1000200):
        print(inst)
        # Check inst properties
        if inst.is_branch:
            print(f"Resolved: {inst.branch_target}")

        for idx, operand in enumerate(inst.operands):
            match operand:
                case lief.assembly.x86.operands.Register():
                    print(f"op[{idx}]: REG - {operand.value}")
                case lief.assembly.x86.operands.Memory():
                    print(f"op[{idx}]: MEM - {operand.base}")
                case lief.assembly.x86.operands.PCRelative():
                    print(f"op[{idx}]: PCR - {operand.value}")
                case lief.assembly.x86.operands.Immediate():
                    print(f"op[{idx}]: IMM - {operand.value}")
    # lief-doc: operands-x86-end


def dwarf_function() -> None:
    # lief-doc: dwarf-func-start
    elf = lief.ELF.parse("/bin/hello")

    main = elf.debug_info.find_function("main")

    for inst in main.instructions:
        print(inst)
    # lief-doc: dwarf-func-end


def x86_lock(inst: lief.assembly.x86.Instruction) -> None:
    # lief-doc: x86-lock-start
    inst: lief.assembly.x86.Instruction

    if inst.has_lock_prefix or inst.is_atomic:
        print(f"{inst} is atomic")
    elif inst.is_lockable and (locked := inst.lock() is not None):
        print(f"atomic version of {inst}: {locked}")
    # lief-doc: x86-lock-end
