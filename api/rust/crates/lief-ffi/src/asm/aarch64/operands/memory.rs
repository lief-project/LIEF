#[repr(C)]
pub struct offset_t {
    pub value: u64,
    pub enum_type: u32,
}

unsafe impl cxx::ExternType for offset_t {
    type Id = cxx::type_id!("asm_aarch64_operands_Memory_offset_t");
    type Kind = cxx::kind::Trivial;
}

#[repr(C)]
pub struct shift_info_t {
    pub enum_type: i32,
    pub value: i8,
}

unsafe impl cxx::ExternType for shift_info_t {
    type Id = cxx::type_id!("asm_aarch64_operands_Memory_shift_info_t");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/aarch64/operands/Memory.hpp");

        type asm_aarch64_Operand = crate::asm::aarch64::operand::ffi::asm_aarch64_Operand;

        type asm_aarch64_operands_Memory_offset_t = crate::asm::aarch64::operands::memory::offset_t;

        type asm_aarch64_operands_Memory;

        type asm_aarch64_operands_Memory_shift_info_t =
            crate::asm::aarch64::operands::memory::shift_info_t;

        #[Self = "asm_aarch64_operands_Memory"]
        fn classof(inst: &asm_aarch64_Operand) -> bool;
        fn base(self: &asm_aarch64_operands_Memory) -> u64;
        fn offset(self: &asm_aarch64_operands_Memory) -> asm_aarch64_operands_Memory_offset_t;
        fn shift(self: &asm_aarch64_operands_Memory) -> asm_aarch64_operands_Memory_shift_info_t;
    }

    impl UniquePtr<asm_aarch64_operands_Memory> {}
}
