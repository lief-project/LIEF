#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/riscv/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type asm_riscv_Operand = crate::asm::riscv::operand::ffi::asm_riscv_Operand;

        type asm_riscv_Instruction;

        #[Self = "asm_riscv_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_riscv_Instruction) -> u64;
        fn operands(self: &asm_riscv_Instruction) -> UniquePtr<asm_riscv_Instruction_it_operands>;

        type asm_riscv_Instruction_it_operands;

        fn next(self: Pin<&mut asm_riscv_Instruction_it_operands>) -> UniquePtr<asm_riscv_Operand>;
        fn size(self: &asm_riscv_Instruction_it_operands) -> u64;
    }
    impl UniquePtr<asm_riscv_Instruction> {}
    impl UniquePtr<asm_riscv_Instruction_it_operands> {}
}
