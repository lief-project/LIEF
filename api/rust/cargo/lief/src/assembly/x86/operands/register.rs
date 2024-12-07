use lief_ffi as ffi;

use crate::assembly::x86::registers::Reg;
use crate::common::FromFFI;

use super::Operand;

/// This structure represents a register operand.
///
/// For instance:
///
/// ```text
/// mov r15d, edi
///      |     |
///      |     +---------> Register(EDI)
///      |
///      +---------------> Register(R15D)
/// ```
pub struct Register {
    ptr: cxx::UniquePtr<ffi::asm_x86_operands_Register>,
}

impl FromFFI<ffi::asm_x86_operands_Register> for Register {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_x86_operands_Register>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Operand for Register {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_x86_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Register {
    /// The effective register wrapped by this operand
    pub fn value(&self) -> Reg {
        Reg::from(self.ptr.value())
    }
}
