#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/riscv/operands/PCRelative.hpp");

        type asm_riscv_Operand = crate::asm::riscv::operand::ffi::asm_riscv_Operand;

        type asm_riscv_operands_PCRelative;

        #[Self = "asm_riscv_operands_PCRelative"]
        fn classof(inst: &asm_riscv_Operand) -> bool;
        fn value(self: &asm_riscv_operands_PCRelative) -> i64;
    }
    impl UniquePtr<asm_riscv_operands_PCRelative> {}
}
