#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/Instruction.hpp");

        type Span = crate::utils::ffi::Span;
        type asm_Instruction;

        fn raw(self: &asm_Instruction) -> Span;

        fn address(self: &asm_Instruction) -> u64;
        fn size(self: &asm_Instruction) -> u64;
        fn mnemonic(self: &asm_Instruction) -> UniquePtr<CxxString>;
        fn to_string(self: &asm_Instruction) -> UniquePtr<CxxString>;
        fn to_string_no_address(self: &asm_Instruction) -> UniquePtr<CxxString>;
        fn is_call(self: &asm_Instruction) -> bool;
        fn is_terminator(self: &asm_Instruction) -> bool;
        fn is_branch(self: &asm_Instruction) -> bool;
        fn is_syscall(self: &asm_Instruction) -> bool;
        fn is_memory_access(self: &asm_Instruction) -> bool;
        fn is_move_reg(self: &asm_Instruction) -> bool;
        fn is_add(self: &asm_Instruction) -> bool;
        fn is_trap(self: &asm_Instruction) -> bool;
        fn is_barrier(self: &asm_Instruction) -> bool;
        fn is_return(self: &asm_Instruction) -> bool;
        fn is_indirect_branch(self: &asm_Instruction) -> bool;
        fn is_conditional_branch(self: &asm_Instruction) -> bool;
        fn is_unconditional_branch(self: &asm_Instruction) -> bool;
        fn is_compare(self: &asm_Instruction) -> bool;
        fn is_move_immediate(self: &asm_Instruction) -> bool;
        fn is_bitcast(self: &asm_Instruction) -> bool;
        fn memory_access(self: &asm_Instruction) -> u64;
        fn branch_target(self: &asm_Instruction, err: Pin<&mut u32>) -> u64;
    }

    impl UniquePtr<asm_Instruction> {}
}
