use lief_ffi as ffi;

use crate::{assembly::ebpf::registers::Reg, common::FromFFI};

use super::Operand;

/// This structure represents a memory operand.
///
/// ```text
/// *(u64 *)(r1 + 8) = r2
///           |    |
///           |    +-----> Displacement: 8
///           |
///           +----------> Base: r1
/// ```
pub struct Memory {
    ptr: cxx::UniquePtr<ffi::asm_ebpf_operands_Memory>,
}

impl FromFFI<ffi::asm_ebpf_operands_Memory> for Memory {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_ebpf_operands_Memory>) -> Self {
        Self { ptr }
    }
}

impl Operand for Memory {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_ebpf_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Memory {
    /// The base register.
    ///
    /// For `*(u64 *)(r1 + 8)` it would return `r1`
    pub fn base(&self) -> Reg {
        Reg::from(self.ptr.base())
    }

    /// The displacement value.
    ///
    /// For `*(u64 *)(r1 + 8)` it would return `8`
    pub fn displacement(&self) -> i64 {
        self.ptr.displacement()
    }
}
