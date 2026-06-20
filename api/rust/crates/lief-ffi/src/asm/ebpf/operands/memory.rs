#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/ebpf/operands/Memory.hpp");

        type asm_ebpf_Operand = crate::asm::ebpf::operand::ffi::asm_ebpf_Operand;

        type asm_ebpf_operands_Memory;

        #[Self = "asm_ebpf_operands_Memory"]
        fn classof(inst: &asm_ebpf_Operand) -> bool;
        fn base(self: &asm_ebpf_operands_Memory) -> u64;
        fn displacement(self: &asm_ebpf_operands_Memory) -> i64;
    }

    impl UniquePtr<asm_ebpf_operands_Memory> {}
}
