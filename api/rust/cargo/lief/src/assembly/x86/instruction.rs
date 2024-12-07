use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::assembly;
use super::Opcode;

use crate::declare_fwd_iterator;
use crate::assembly::x86;

/// This structure represents a x86/x86-64 instruction
pub struct Instruction {
    ptr: cxx::UniquePtr<ffi::asm_x86_Instruction>,
}

impl FromFFI<ffi::asm_x86_Instruction> for Instruction {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_x86_Instruction>) -> Self {
        Self {
            ptr,
        }
    }
}

impl assembly::Instruction for Instruction {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_Instruction {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Instruction {
    /// The instruction opcode as defined in LLVM
    pub fn opcode(&self) -> Opcode {
        Opcode::from(self.ptr.opcode())
    }

    /// Return an iterator over the [`x86::Operands`] operands
    pub fn operands(&self) -> Operands {
        Operands::new(self.ptr.operands())
    }
}

declare_fwd_iterator!(
    Operands,
    x86::Operands,
    ffi::asm_Instruction,
    ffi::asm_x86_Operand,
    ffi::asm_x86_Instruction_it_operands
);
