use lief_ffi as ffi;

use crate::{assembly::x86::registers::Reg, common::FromFFI};

use super::Operand;

/// This structure represents a memory operand.
///
/// For instance:
///
/// ```text
/// movq xmm3, qword ptr [rip + 823864];
///
///                      |
///                      |
///                    Memory
///                      |
///          +-----------+-----------+
///          |           |           |
///      Base: rip    Scale: 1    Displacement: 823864
///
/// ```
pub struct Memory {
    ptr: cxx::UniquePtr<ffi::asm_x86_operands_Memory>,
}

impl FromFFI<ffi::asm_x86_operands_Memory> for Memory {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_x86_operands_Memory>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Operand for Memory {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_x86_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Memory {
    /// The base register.
    ///
    /// For `lea rdx, [rip + 244634]` it would return [`Reg::RIP`]
    pub fn base(&self) -> Reg {
        Reg::from(self.ptr.base())
    }

    /// The scaled register.
    ///
    /// For `mov rdi, qword ptr [r13 + 8*r14]` it would return [`Reg::R14`]
    pub fn scaled_register(&self) -> Reg {
        Reg::from(self.ptr.scaled_register())
    }

    /// The segment register associated with the memory operation.
    ///
    /// For `mov eax, dword ptr gs:[0]` is would return [`Reg::GS`]
    pub fn segment_register(&self) -> Reg {
        Reg::from(self.ptr.segment_register())
    }

    /// The scale value associated with the [`Memory::scaled_register`]
    ///
    /// For `mov rdi, qword ptr [r13 + 8*r14]` it would return `8`
    pub fn scale(&self) -> u64 {
        self.ptr.scale()
    }

    /// The displacement value
    ///
    /// For `call qword ptr [rip + 248779]` it would return `248779`
    pub fn displacement(&self) -> i64 {
        self.ptr.displacement()
    }
}
