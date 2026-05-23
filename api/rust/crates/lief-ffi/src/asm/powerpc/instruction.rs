#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/powerpc/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;

        type asm_powerpc_Instruction;

        #[Self = "asm_powerpc_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_powerpc_Instruction) -> u64;
    }
    impl UniquePtr<asm_powerpc_Instruction> {}
}
