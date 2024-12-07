use lief_ffi as ffi;

use crate::common::FromFFI;

use super::Operand;

/// This structure represents an immediate operand.
///
/// For instance:
///
/// ```text
/// mov edi, 1;
///          |
///          +---> Immediate(1)
/// ```
pub struct Immediate {
    ptr: cxx::UniquePtr<ffi::asm_x86_operands_Immediate>,
}

impl FromFFI<ffi::asm_x86_operands_Immediate> for Immediate {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_x86_operands_Immediate>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Operand for Immediate {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_x86_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Immediate {
    /// The constant value wrapped by this operand
    pub fn value(&self) -> i64 {
        self.ptr.value()
    }
}
