use lief_ffi as ffi;

use crate::common::FromFFI;

pub mod immediate;
pub mod memory;
pub mod pc_relative;
pub mod register;

#[doc(inline)]
pub use register::Register;

#[doc(inline)]
pub use pc_relative::PCRelative;

#[doc(inline)]
pub use immediate::Immediate;

#[doc(inline)]
pub use memory::Memory;

/// Trait shared by **all** [`Operands`]
pub trait Operand {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_aarch64_Operand;

    /// Pretty representation of the operand
    fn to_string(&self) -> String {
        self.as_generic().to_string().to_string()
    }
}

/// This enum represents the different kind of operands associated with [`super::Instruction`]
pub enum Operands {
    /// A register operand (e.g. `X0`)
    Reg(Register),

    /// A PC-relative operand
    PCRelative(PCRelative),

    /// An immediate value
    Imm(Immediate),

    /// A memory operand
    Mem(Memory),

    /// Operand that is not correctly supported
    Unknown(Unknown),
}

impl FromFFI<ffi::asm_aarch64_Operand> for Operands {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_aarch64_Operand>) -> Self {
        unsafe {
            let op_ref = ptr.as_ref().unwrap();
            if ffi::asm_aarch64_operands_Memory::classof(op_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::asm_aarch64_Operand>;
                    type To   = cxx::UniquePtr<ffi::asm_aarch64_operands_Memory>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Operands::Mem(Memory::from_ffi(raw));
            }
            else if ffi::asm_aarch64_operands_Register::classof(op_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::asm_aarch64_Operand>;
                    type To   = cxx::UniquePtr<ffi::asm_aarch64_operands_Register>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Operands::Reg(Register::from_ffi(raw));
            }
            else if ffi::asm_aarch64_operands_Immediate::classof(op_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::asm_aarch64_Operand>;
                    type To   = cxx::UniquePtr<ffi::asm_aarch64_operands_Immediate>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Operands::Imm(Immediate::from_ffi(raw));
            }
            else if ffi::asm_aarch64_operands_PCRelative::classof(op_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::asm_aarch64_Operand>;
                    type To   = cxx::UniquePtr<ffi::asm_aarch64_operands_PCRelative>;
                    std::mem::transmute::<From, To>(ptr)
                };
                return Operands::PCRelative(PCRelative::from_ffi(raw));
            }
            return Operands::Unknown(Unknown::from_ffi(ptr));
        }
    }
}

impl Operand for Operands {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_aarch64_Operand {
        match &self {
            Operands::Reg(op) => {
                op.as_generic()
            }

            Operands::Imm(op) => {
                op.as_generic()
            }

            Operands::Mem(op) => {
                op.as_generic()
            }

            Operands::PCRelative(op) => {
                op.as_generic()
            }

            Operands::Unknown(op) => {
                op.as_generic()
            }
        }
    }
}

pub struct Unknown {
    ptr: cxx::UniquePtr<ffi::asm_aarch64_Operand>,
}

impl FromFFI<ffi::asm_aarch64_Operand> for Unknown {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_aarch64_Operand>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Operand for Unknown {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_aarch64_Operand {
        self.ptr.as_ref().unwrap()
    }
}



