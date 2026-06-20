#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/mips/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type asm_mips_Operand = crate::asm::mips::operand::ffi::asm_mips_Operand;

        type asm_mips_Instruction;

        #[Self = "asm_mips_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_mips_Instruction) -> u64;
        fn operands(self: &asm_mips_Instruction) -> UniquePtr<asm_mips_Instruction_it_operands>;

        type asm_mips_Instruction_it_operands;

        fn next(self: Pin<&mut asm_mips_Instruction_it_operands>) -> UniquePtr<asm_mips_Operand>;
        fn size(self: &asm_mips_Instruction_it_operands) -> u64;
    }
    impl UniquePtr<asm_mips_Instruction> {}
    impl UniquePtr<asm_mips_Instruction_it_operands> {}
}
