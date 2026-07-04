#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/ebpf/Instruction.hpp");

        type asm_Instruction = crate::asm::instruction::ffi::asm_Instruction;
        type asm_ebpf_Operand = crate::asm::ebpf::operand::ffi::asm_ebpf_Operand;

        type asm_ebpf_Instruction;

        #[Self = "asm_ebpf_Instruction"]
        fn classof(inst: &asm_Instruction) -> bool;
        fn opcode(self: &asm_ebpf_Instruction) -> u64;
        fn operands(self: &asm_ebpf_Instruction) -> UniquePtr<asm_ebpf_Instruction_it_operands>;

        type asm_ebpf_Instruction_it_operands;

        fn next(self: Pin<&mut asm_ebpf_Instruction_it_operands>) -> UniquePtr<asm_ebpf_Operand>;
        fn size(self: &asm_ebpf_Instruction_it_operands) -> u64;
    }
    impl UniquePtr<asm_ebpf_Instruction> {}
    impl UniquePtr<asm_ebpf_Instruction_it_operands> {}
}
