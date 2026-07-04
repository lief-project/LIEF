#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/riscv/Operand.hpp");

        type asm_riscv_Operand;

        fn to_string(self: &asm_riscv_Operand) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<asm_riscv_Operand> {}
}
