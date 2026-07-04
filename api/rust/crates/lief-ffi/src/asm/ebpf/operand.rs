#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/ebpf/Operand.hpp");

        type asm_ebpf_Operand;

        fn to_string(self: &asm_ebpf_Operand) -> UniquePtr<CxxString>;
    }

    impl UniquePtr<asm_ebpf_Operand> {}
}
