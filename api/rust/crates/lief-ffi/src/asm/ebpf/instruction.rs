#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/ebpf/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;

        type asm_ebpf_Instruction;

        #[Self = "asm_ebpf_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_ebpf_Instruction) -> u64;
    }
    impl UniquePtr<asm_ebpf_Instruction> {}
}
