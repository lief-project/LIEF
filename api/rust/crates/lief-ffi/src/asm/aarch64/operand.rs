#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/aarch64/Operand.hpp");

        type asm_aarch64_Operand;

        fn to_string(self: &asm_aarch64_Operand) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<asm_aarch64_Operand> {}
}
