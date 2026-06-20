#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/mips/Operand.hpp");

        type asm_mips_Operand;

        fn to_string(self: &asm_mips_Operand) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<asm_mips_Operand> {}
}
