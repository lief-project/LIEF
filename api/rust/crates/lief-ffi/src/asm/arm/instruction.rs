#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/arm/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;

        type asm_arm_Instruction;

        #[Self = "asm_arm_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_arm_Instruction) -> u64;
    }
    impl UniquePtr<asm_arm_Instruction> {}
}
