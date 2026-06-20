use lief_ffi as ffi;

use crate::{assembly::riscv::registers::Reg, common::FromFFI};

use super::Operand;

/// This structure represents a memory operand.
///
/// ```text
/// lw   a0, 8(sp)
///          |  |
///          |  +----> Base: sp
///          |
///          +-------> Displacement: 8
/// ```
pub struct Memory {
    ptr: cxx::UniquePtr<ffi::asm_riscv_operands_Memory>,
}

impl FromFFI<ffi::asm_riscv_operands_Memory> for Memory {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_riscv_operands_Memory>) -> Self {
        Self { ptr }
    }
}

impl Operand for Memory {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_riscv_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Memory {
    /// The base register.
    ///
    /// For `lw a0, 8(sp)` it would return `sp`
    pub fn base(&self) -> Reg {
        Reg::from(self.ptr.base())
    }

    /// The displacement value.
    ///
    /// For `lw a0, 8(sp)` it would return `8`
    pub fn displacement(&self) -> i64 {
        self.ptr.displacement()
    }
}
