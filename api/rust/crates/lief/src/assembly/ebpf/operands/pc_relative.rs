use lief_ffi as ffi;

use crate::common::FromFFI;

use super::Operand;

/// This structure represents a PC-relative operand.
///
/// ```text
/// if r1 == 0 goto +5
///                 |
///                 v
///         PC Relative operand
/// ```
pub struct PCRelative {
    ptr: cxx::UniquePtr<ffi::asm_ebpf_operands_PCRelative>,
}

impl FromFFI<ffi::asm_ebpf_operands_PCRelative> for PCRelative {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_ebpf_operands_PCRelative>) -> Self {
        Self { ptr }
    }
}

impl Operand for PCRelative {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_ebpf_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl PCRelative {
    /// The effective value that is relative to the current `pc` register
    pub fn value(&self) -> i64 {
        self.ptr.value()
    }
}
