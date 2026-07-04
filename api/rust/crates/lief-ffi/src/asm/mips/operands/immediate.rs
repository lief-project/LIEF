#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/mips/operands/Immediate.hpp");

        type asm_mips_Operand = crate::asm::mips::operand::ffi::asm_mips_Operand;

        type asm_mips_operands_Immediate;

        #[Self = "asm_mips_operands_Immediate"]
        fn classof(inst: &asm_mips_Operand) -> bool;
        fn value(self: &asm_mips_operands_Immediate) -> i64;
    }
    impl UniquePtr<asm_mips_operands_Immediate> {}
}
