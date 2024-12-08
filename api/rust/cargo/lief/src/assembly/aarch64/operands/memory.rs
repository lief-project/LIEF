use lief_ffi as ffi;

use crate::{assembly::aarch64::registers::Reg, common::FromFFI};

use super::Operand;

/// This structure represents a memory operand.
///
/// ```text
/// ldr     x0, [x1, x2, lsl #3]
///              |   |    |
/// +------------+   |    +--------+
/// |                |             |
/// v                v             v
/// Base            Reg Offset    Shift
///
/// ```
pub struct Memory {
    ptr: cxx::UniquePtr<ffi::asm_aarch64_operands_Memory>,
}

impl FromFFI<ffi::asm_aarch64_operands_Memory> for Memory {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_aarch64_operands_Memory>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Operand for Memory {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_aarch64_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

/// Wraps a memory offset as an integer offset or as a register offset
#[derive(Debug)]
pub enum Offset {
    /// Register offset
    Reg(Reg),
    /// Integer offset
    Displacement(i64),
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Shift {
    Unknown,
    Lsl,
    Uxtx,
    Uxtw,
    Sxtx,
    Sxtw,
}

impl From<i32> for Shift {
    fn from(value: i32) -> Self {
        match value {
          0 => Shift::Unknown,
          1 => Shift::Lsl,
          2 => Shift::Uxtx,
          3 => Shift::Uxtw,
          4 => Shift::Sxtx,
          5 => Shift::Sxtw,
          _ => Shift::Unknown,
        }
    }
}

/// This structure holds shift info (type + value)
#[derive(Debug)]
pub struct ShiftInfo {
    pub shift_type: Shift,
    pub value: i8,
}

impl ShiftInfo {
    pub fn new(shift: Shift, value: i8) -> Self {
        Self {
            shift_type: shift,
            value
        }
    }
}

impl Memory {
    /// The base register.
    ///
    /// For `str x3, [x8, #8]` it would return `x8`
    pub fn base(&self) -> Reg {
        Reg::from(self.ptr.base())
    }

    /// The addressing offset.
    ///
    /// It can be either:
    /// - A register (e.g. `ldr x0, [x1, x3]`)
    /// - An offset (e.g. `ldr x0, [x1, #8]`)
    pub fn offset(&self) -> Option<Offset> {
        let ffi_offset = self.ptr.offset();
        match ffi_offset.enum_type {
            1 => {
                Some(Offset::Reg(Reg::from(ffi_offset.value)))
            }
            2 => {
                Some(Offset::Displacement(ffi_offset.value as i64))
            }
            _ => {
                None
            }
        }
    }

    /// Shift information.
    ///
    /// For instance, for `ldr x1, [x2, x3, lsl #3]` it would
    /// return a [`Shift::Lsl`] with a [`ShiftInfo::value`] set to `3`
    pub fn shift(&self) -> Option<ShiftInfo> {
        let ffi_shift = self.ptr.shift();
        if ffi_shift.value == 0 {
            return None;
        }
        Some(ShiftInfo::new(Shift::from(ffi_shift.enum_type), ffi_shift.value))
    }
}
