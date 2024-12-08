use lief_ffi as ffi;

use crate::assembly::aarch64::registers::{Reg, SysReg};
use crate::common::FromFFI;

use super::Operand;

/// This structure represents a register operand.
///
/// ```text
/// mrs     x0, TPIDR_EL0
///         |   |
///  +------+   +-------+
///  |                  |
///  v                  v
///  REG              SYSREG
/// ```
pub struct Register {
    ptr: cxx::UniquePtr<ffi::asm_aarch64_operands_Register>,
}

impl FromFFI<ffi::asm_aarch64_operands_Register> for Register {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_aarch64_operands_Register>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Operand for Register {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_aarch64_Operand {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

#[derive(Debug)]
pub enum Value {
    Reg(Reg),
    SysReg(SysReg),
}

impl Register {
    /// The effective register as either: a [`Reg`] or a [`SysReg`]
    pub fn value(&self) -> Option<Value> {
        let ffi_value = self.ptr.value();
        match ffi_value.enum_type {
            1 => {
                Some(Value::SysReg(SysReg::from(ffi_value.reg)))
            }
            2 => {
                Some(Value::Reg(Reg::from(ffi_value.reg)))
            }
            _ => {
                None
            }
        }
    }
}
