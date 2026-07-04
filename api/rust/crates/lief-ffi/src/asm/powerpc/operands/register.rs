#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/powerpc/operands/Register.hpp");

        type asm_powerpc_Operand = crate::asm::powerpc::operand::ffi::asm_powerpc_Operand;

        type asm_powerpc_operands_Register;

        #[Self = "asm_powerpc_operands_Register"]
        fn classof(inst: &asm_powerpc_Operand) -> bool;
        fn value(self: &asm_powerpc_operands_Register) -> u64;
    }
    impl UniquePtr<asm_powerpc_operands_Register> {}
}
