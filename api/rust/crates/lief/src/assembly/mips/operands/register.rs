use lief_ffi as ffi;

use crate::assembly::mips::registers::Reg;
use crate::common::FromFFI;

use super::Operand;

/// This structure represents a register operand.
///
/// For instance:
///
/// ```text
/// move $4, $5
///       |   |
///       |   +---------> Register($5)
///       |
///       +-------------> Register($4)
/// ```
pub struct Register {
    ptr: cxx::UniquePtr<ffi::asm_mips_operands_Register>,
}

impl FromFFI<ffi::asm_mips_operands_Register> for Register {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_mips_operands_Register>) -> Self {
        Self { ptr }
    }
}

impl Operand for Register {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_mips_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Register {
    /// The effective register wrapped by this operand
    pub fn value(&self) -> Reg {
        Reg::from(self.ptr.value())
    }
}
