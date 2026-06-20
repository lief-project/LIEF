use lief_ffi as ffi;

use crate::{assembly::powerpc::registers::Reg, common::FromFFI};

use super::Operand;

/// This structure represents a memory operand.
///
/// ```text
/// lwz   3, 8(4)              lwzx   3, 4, 5
///        |  |                       |  |  |
/// +------+  +---+            +------+   |  +---+
/// |             |           |          |      |
/// v             v           v          v      v
/// Disp         Base        Reg        Base   Index
/// ```
pub struct Memory {
    ptr: cxx::UniquePtr<ffi::asm_powerpc_operands_Memory>,
}

impl FromFFI<ffi::asm_powerpc_operands_Memory> for Memory {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_powerpc_operands_Memory>) -> Self {
        Self { ptr }
    }
}

impl Operand for Memory {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_powerpc_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// Wraps a memory offset as an integer displacement or as an index register
#[derive(Debug)]
pub enum Offset {
    /// Index register offset
    Reg(Reg),
    /// Integer displacement
    Displacement(i64),
}

impl Memory {
    /// The base register.
    ///
    /// For `lwz 3, 8(4)` it would return `4`
    pub fn base(&self) -> Reg {
        Reg::from(self.ptr.base())
    }

    /// The addressing offset.
    ///
    /// It can be either:
    /// - An index register (e.g. `lwzx 3, 4, 5`)
    /// - A displacement (e.g. `lwz 3, 8(4)`)
    pub fn offset(&self) -> Option<Offset> {
        let ffi_offset = self.ptr.offset();
        match ffi_offset.enum_type {
            1 => Some(Offset::Reg(Reg::from(ffi_offset.value))),
            2 => Some(Offset::Displacement(ffi_offset.value as i64)),
            _ => None,
        }
    }
}
