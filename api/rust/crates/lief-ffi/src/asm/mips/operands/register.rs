#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/mips/operands/Register.hpp");

        type asm_mips_Operand = crate::asm::mips::operand::ffi::asm_mips_Operand;

        type asm_mips_operands_Register;

        #[Self = "asm_mips_operands_Register"]
        fn classof(inst: &asm_mips_Operand) -> bool;
        fn value(self: &asm_mips_operands_Register) -> u64;
    }
    impl UniquePtr<asm_mips_operands_Register> {}
}
