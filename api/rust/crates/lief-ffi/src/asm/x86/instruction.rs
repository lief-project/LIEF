#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/x86/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type asm_x86_Operand = crate::asm::x86::operand::ffi::asm_x86_Operand;

        type asm_x86_Instruction;

        #[Self = "asm_x86_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_x86_Instruction) -> u64;
        fn operands(self: &asm_x86_Instruction) -> UniquePtr<asm_x86_Instruction_it_operands>;

        type asm_x86_Instruction_it_operands;

        fn next(self: Pin<&mut asm_x86_Instruction_it_operands>) -> UniquePtr<asm_x86_Operand>;
        fn size(self: &asm_x86_Instruction_it_operands) -> u64;
    }
    impl UniquePtr<asm_x86_Instruction> {}
    impl UniquePtr<asm_x86_Instruction_it_operands> {}
}
