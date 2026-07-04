#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/x86/operands/PCRelative.hpp");

        type asm_x86_Operand = crate::asm::x86::operand::ffi::asm_x86_Operand;

        type asm_x86_operands_PCRelative;

        #[Self = "asm_x86_operands_PCRelative"]
        fn classof(inst: &asm_x86_Operand) -> bool;
        fn value(self: &asm_x86_operands_PCRelative) -> i64;
    }
    impl UniquePtr<asm_x86_operands_PCRelative> {}
}
