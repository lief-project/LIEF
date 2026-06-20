#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/powerpc/operands/PCRelative.hpp");

        type asm_powerpc_Operand = crate::asm::powerpc::operand::ffi::asm_powerpc_Operand;

        type asm_powerpc_operands_PCRelative;

        #[Self = "asm_powerpc_operands_PCRelative"]
        fn classof(inst: &asm_powerpc_Operand) -> bool;
        fn value(self: &asm_powerpc_operands_PCRelative) -> i64;
    }
    impl UniquePtr<asm_powerpc_operands_PCRelative> {}
}
