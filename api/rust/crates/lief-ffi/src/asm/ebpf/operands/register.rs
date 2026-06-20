#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/ebpf/operands/Register.hpp");

        type asm_ebpf_Operand = crate::asm::ebpf::operand::ffi::asm_ebpf_Operand;

        type asm_ebpf_operands_Register;

        #[Self = "asm_ebpf_operands_Register"]
        fn classof(inst: &asm_ebpf_Operand) -> bool;
        fn value(self: &asm_ebpf_operands_Register) -> u64;
    }
    impl UniquePtr<asm_ebpf_operands_Register> {}
}
