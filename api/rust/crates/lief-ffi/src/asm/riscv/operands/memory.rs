#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/riscv/operands/Memory.hpp");

        type asm_riscv_Operand = crate::asm::riscv::operand::ffi::asm_riscv_Operand;

        type asm_riscv_operands_Memory;

        #[Self = "asm_riscv_operands_Memory"]
        fn classof(inst: &asm_riscv_Operand) -> bool;
        fn base(self: &asm_riscv_operands_Memory) -> u64;
        fn displacement(self: &asm_riscv_operands_Memory) -> i64;
    }

    impl UniquePtr<asm_riscv_operands_Memory> {}
}
