#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/x86/Operand.hpp");

        type asm_x86_Operand;

        fn to_string(self: &asm_x86_Operand) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<asm_x86_Operand> {}
}
