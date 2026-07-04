#[repr(C)]
pub struct reg_t {
    pub reg: u64,
    pub enum_type: u32,
}

unsafe impl cxx::ExternType for reg_t {
    type Id = cxx::type_id!("asm_aarch64_operands_Register_reg_t");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/aarch64/operands/Register.hpp");

        type asm_aarch64_Operand = crate::asm::aarch64::operand::ffi::asm_aarch64_Operand;

        type asm_aarch64_operands_Register;

        type asm_aarch64_operands_Register_reg_t = crate::asm::aarch64::operands::register::reg_t;

        #[Self = "asm_aarch64_operands_Register"]
        fn classof(inst: &asm_aarch64_Operand) -> bool;
        fn value(self: &asm_aarch64_operands_Register) -> asm_aarch64_operands_Register_reg_t;
    }
    impl UniquePtr<asm_aarch64_operands_Register> {}
}
