#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/x86/operands/Register.hpp");

        type asm_x86_Operand = crate::asm::x86::operand::ffi::asm_x86_Operand;

        type asm_x86_operands_Register;

        #[Self = "asm_x86_operands_Register"]
        fn classof(inst: &asm_x86_Operand) -> bool;
        fn value(self: &asm_x86_operands_Register) -> u64;
    }
    impl UniquePtr<asm_x86_operands_Register> {}
}
