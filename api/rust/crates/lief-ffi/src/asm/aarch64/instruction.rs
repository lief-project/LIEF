#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/aarch64/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type asm_aarch64_Operand = crate::asm::aarch64::operand::ffi::asm_aarch64_Operand;

        type asm_aarch64_Instruction;

        #[Self = "asm_aarch64_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_aarch64_Instruction) -> u64;
        fn operands(
            self: &asm_aarch64_Instruction,
        ) -> UniquePtr<asm_aarch64_Instruction_it_operands>;

        type asm_aarch64_Instruction_it_operands;

        fn next(
            self: Pin<&mut asm_aarch64_Instruction_it_operands>,
        ) -> UniquePtr<asm_aarch64_Operand>;
        fn size(self: &asm_aarch64_Instruction_it_operands) -> u64;
    }
    impl UniquePtr<asm_aarch64_Instruction> {}
    impl UniquePtr<asm_aarch64_Instruction_it_operands> {}
}
