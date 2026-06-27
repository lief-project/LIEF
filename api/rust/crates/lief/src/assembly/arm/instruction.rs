use lief_ffi as ffi;

use super::Opcode;
use crate::assembly;
use crate::common::FromFFI;

/// This structure represents an ARM/Thumb instruction
pub struct Instruction {
    ptr: cxx::UniquePtr<ffi::asm_arm_Instruction>,
}

impl FromFFI<ffi::asm_arm_Instruction> for Instruction {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_arm_Instruction>) -> Self {
        Self { ptr }
    }
}

impl assembly::Instruction for Instruction {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_Instruction {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", assembly::Instruction::as_generic(self).to_string())
    }
}

impl Instruction {
    /// The instruction opcode as defined in LLVM
    pub fn opcode(&self) -> Opcode {
        Opcode::from(self.ptr.opcode())
    }
}
