#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/aarch64/operands/PCRelative.hpp");

        type asm_aarch64_Operand = crate::asm::aarch64::operand::ffi::asm_aarch64_Operand;

        type asm_aarch64_operands_PCRelative;

        #[Self = "asm_aarch64_operands_PCRelative"]
        fn classof(inst: &asm_aarch64_Operand) -> bool;
        fn value(self: &asm_aarch64_operands_PCRelative) -> i64;
    }
    impl UniquePtr<asm_aarch64_operands_PCRelative> {}
}
