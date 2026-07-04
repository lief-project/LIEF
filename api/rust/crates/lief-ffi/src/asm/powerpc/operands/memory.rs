#[repr(C)]
pub struct offset_t {
    pub value: u64,
    pub enum_type: u32,
}

unsafe impl cxx::ExternType for offset_t {
    type Id = cxx::type_id!("asm_powerpc_operands_Memory_offset_t");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/powerpc/operands/Memory.hpp");

        type asm_powerpc_Operand = crate::asm::powerpc::operand::ffi::asm_powerpc_Operand;

        type asm_powerpc_operands_Memory_offset_t = crate::asm::powerpc::operands::memory::offset_t;

        type asm_powerpc_operands_Memory;

        #[Self = "asm_powerpc_operands_Memory"]
        fn classof(inst: &asm_powerpc_Operand) -> bool;
        fn base(self: &asm_powerpc_operands_Memory) -> u64;
        fn offset(self: &asm_powerpc_operands_Memory) -> asm_powerpc_operands_Memory_offset_t;
    }

    impl UniquePtr<asm_powerpc_operands_Memory> {}
}
