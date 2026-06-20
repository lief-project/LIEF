#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/powerpc/Operand.hpp");

        type asm_powerpc_Operand;

        fn to_string(self: &asm_powerpc_Operand) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<asm_powerpc_Operand> {}
}
