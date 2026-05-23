#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/aarch64/operands/Immediate.hpp");

        type asm_aarch64_Operand = crate::asm::aarch64::operand::ffi::asm_aarch64_Operand;

        type asm_aarch64_operands_Immediate;

        #[Self = "asm_aarch64_operands_Immediate"]
        fn classof(inst: &asm_aarch64_Operand) -> bool;
        fn value(self: &asm_aarch64_operands_Immediate) -> i64;
    }
    impl UniquePtr<asm_aarch64_operands_Immediate> {}
}
