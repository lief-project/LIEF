#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/x86/operands/Memory.hpp");

        type asm_x86_Operand = crate::asm::x86::operand::ffi::asm_x86_Operand;

        type asm_x86_operands_Memory;

        #[Self = "asm_x86_operands_Memory"]
        fn classof(inst: &asm_x86_Operand) -> bool;
        fn base(self: &asm_x86_operands_Memory) -> u64;
        fn scaled_register(self: &asm_x86_operands_Memory) -> u64;
        fn segment_register(self: &asm_x86_operands_Memory) -> u64;
        fn scale(self: &asm_x86_operands_Memory) -> u64;
        fn displacement(self: &asm_x86_operands_Memory) -> i64;
    }
    impl UniquePtr<asm_x86_operands_Memory> {}
}
