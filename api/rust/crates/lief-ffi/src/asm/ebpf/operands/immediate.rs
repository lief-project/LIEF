#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/ebpf/operands/Immediate.hpp");

        type asm_ebpf_Operand = crate::asm::ebpf::operand::ffi::asm_ebpf_Operand;

        type asm_ebpf_operands_Immediate;

        #[Self = "asm_ebpf_operands_Immediate"]
        fn classof(inst: &asm_ebpf_Operand) -> bool;
        fn value(self: &asm_ebpf_operands_Immediate) -> i64;
    }
    impl UniquePtr<asm_ebpf_operands_Immediate> {}
}
