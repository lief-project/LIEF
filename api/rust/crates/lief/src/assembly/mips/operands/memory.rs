use lief_ffi as ffi;

use crate::{assembly::mips::registers::Reg, common::FromFFI};

use super::Operand;

/// This structure represents a memory operand.
///
/// ```text
/// lw    $4, 8($5)            ldxc1  $f2, $4($7)
///        |  | |                      |   |  |
/// +------+  | +---+          +-------+   |  +-----+
/// |         |     |          |           |        |
/// v         v     v          v           v        v
/// Reg      Disp  Base       Reg         Index    Base
/// ```
pub struct Memory {
    ptr: cxx::UniquePtr<ffi::asm_mips_operands_Memory>,
}

impl FromFFI<ffi::asm_mips_operands_Memory> for Memory {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_mips_operands_Memory>) -> Self {
        Self { ptr }
    }
}

impl Operand for Memory {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_mips_Operand {
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
    /// For `lw $4, 8($5)` it would return `$5`
    pub fn base(&self) -> Reg {
        Reg::from(self.ptr.base())
    }

    /// The addressing offset.
    ///
    /// It can be either:
    /// - A register (e.g. `ldxc1 $f2, $4($7)`)
    /// - A displacement (e.g. `lw $4, 8($5)`)
    pub fn offset(&self) -> Option<Offset> {
        let ffi_offset = self.ptr.offset();
        match ffi_offset.enum_type {
            1 => Some(Offset::Reg(Reg::from(ffi_offset.value))),
            2 => Some(Offset::Displacement(ffi_offset.value as i64)),
            _ => None,
        }
    }
}
