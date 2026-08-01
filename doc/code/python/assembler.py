from typing import override

import lief


def disassemble_assemble(elf: lief.ELF.Binary) -> None:
    # lief-doc: disassemble-assemble-start
    elf: lief.ELF.Binary

    syscall_addresses = [
        inst.address for inst in elf.disassemble(0x400090) if inst.is_syscall
    ]

    for syscall_addr in syscall_addresses:
        elf.assemble(
            syscall_addr,
            """
            mov x1, x0;
            str x1, [x2, #8];
            """,
        )
    # lief-doc: disassemble-assemble-end


def context_error(elf: lief.ELF.Binary) -> None:
    # lief-doc: context-error-start
    elf: lief.ELF.Binary

    elf.assemble(
        elf.entrypoint,
        """
        mov rdi, rax;
        call a_custom_function;
        """,
    )
    # lief-doc: context-error-end


def config_resolver(elf: lief.ELF.Binary) -> None:
    # lief-doc: config-resolver-start
    class MyConfig(lief.assembly.AssemblerConfig):
        def __init__(self):
            super().__init__()  # Important!

        @override
        def resolve_symbol(self, name: str) -> int | None:
            if name == "a_custom_function":
                return 0x1000
            return None

    elf: lief.ELF.Binary

    elf.assemble(
        elf.entrypoint,
        """
        mov rdi, rax;
        call a_custom_function;
        """,
        MyConfig(),
    )
    # lief-doc: config-resolver-end


def config_target(elf: lief.ELF.Binary) -> None:
    # lief-doc: config-target-start
    class MyConfig(lief.assembly.AssemblerConfig):
        def __init__(self, target: lief.Binary):
            super().__init__()  # Important!

            self._target = target

        @override
        def resolve_symbol(self, name: str) -> int | None:
            addr = self._target.get_function_address(name)
            if isinstance(addr, lief.lief_errors):
                return None
            return addr

    elf: lief.ELF.Binary
    config = MyConfig(elf)

    elf.assemble(
        elf.entrypoint,
        """
        mov rdi, rax;
        call a_custom_function;
        """,
        config,
    )
    # lief-doc: config-target-end


def disable_instruction(elf: lief.ELF.Binary) -> None:
    # lief-doc: nop-out-start
    elf: lief.ELF.Binary

    # Overwrite the first call in the region (e.g. a call to an anti-debugging
    # routine) with nops
    for inst in elf.disassemble(0x401200):
        if inst.is_call:
            elf.assemble(inst.address, "nop\n" * inst.size)
            break

    elf.write("patched.bin")
    # lief-doc: nop-out-end
