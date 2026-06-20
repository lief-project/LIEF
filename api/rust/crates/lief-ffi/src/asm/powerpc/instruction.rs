#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/powerpc/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type asm_powerpc_Operand = crate::asm::powerpc::operand::ffi::asm_powerpc_Operand;

        type asm_powerpc_Instruction;

        #[Self = "asm_powerpc_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_powerpc_Instruction) -> u64;
        fn operands(
            self: &asm_powerpc_Instruction,
        ) -> UniquePtr<asm_powerpc_Instruction_it_operands>;

        type asm_powerpc_Instruction_it_operands;

        fn next(
            self: Pin<&mut asm_powerpc_Instruction_it_operands>,
        ) -> UniquePtr<asm_powerpc_Operand>;
        fn size(self: &asm_powerpc_Instruction_it_operands) -> u64;
    }
    impl UniquePtr<asm_powerpc_Instruction> {}
    impl UniquePtr<asm_powerpc_Instruction_it_operands> {}
}
