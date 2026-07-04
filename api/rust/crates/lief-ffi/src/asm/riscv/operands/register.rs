#[repr(C)]
pub struct reg_t {
    pub reg: u64,
    pub enum_type: u32,
}

unsafe impl cxx::ExternType for reg_t {
    type Id = cxx::type_id!("asm_riscv_operands_Register_reg_t");
    type Kind = cxx::kind::Trivial;
}

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("LIEF/rust/asm/riscv/operands/Register.hpp");

        type asm_riscv_Operand = crate::asm::riscv::operand::ffi::asm_riscv_Operand;

        type asm_riscv_operands_Register;

        type asm_riscv_operands_Register_reg_t = crate::asm::riscv::operands::register::reg_t;

        #[Self = "asm_riscv_operands_Register"]
        fn classof(inst: &asm_riscv_Operand) -> bool;
        fn value(self: &asm_riscv_operands_Register) -> asm_riscv_operands_Register_reg_t;
    }
    impl UniquePtr<asm_riscv_operands_Register> {}
}
