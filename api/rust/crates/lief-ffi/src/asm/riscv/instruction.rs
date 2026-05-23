#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/riscv/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;

        type asm_riscv_Instruction;

        #[Self = "asm_riscv_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_riscv_Instruction) -> u64;
    }
    impl UniquePtr<asm_riscv_Instruction> {}
}
