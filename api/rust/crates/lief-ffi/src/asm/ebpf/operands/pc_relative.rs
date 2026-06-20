#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/ebpf/operands/PCRelative.hpp");

        type asm_ebpf_Operand = crate::asm::ebpf::operand::ffi::asm_ebpf_Operand;

        type asm_ebpf_operands_PCRelative;

        #[Self = "asm_ebpf_operands_PCRelative"]
        fn classof(inst: &asm_ebpf_Operand) -> bool;
        fn value(self: &asm_ebpf_operands_PCRelative) -> i64;
    }
    impl UniquePtr<asm_ebpf_operands_PCRelative> {}
}
