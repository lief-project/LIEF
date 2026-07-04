use lief_ffi as ffi;

use super::Opcode;
use crate::assembly;
use crate::common::FromFFI;

use crate::assembly::mips;
use crate::declare_fwd_iterator;

/// This structure represents a Mips instruction (including mips64, mips32)
pub struct Instruction {
    ptr: cxx::UniquePtr<ffi::asm_mips_Instruction>,
}

impl FromFFI<ffi::asm_mips_Instruction> for Instruction {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_mips_Instruction>) -> Self {
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

    /// Return an iterator over the [`mips::Operands`] operands
    pub fn operands(&self) -> Operands<'_> {
        Operands::new(self.ptr.operands())
    }
}

declare_fwd_iterator!(
    Operands,
    mips::Operands,
    ffi::asm_Instruction,
    ffi::asm_mips_Operand,
    ffi::asm_mips_Instruction_it_operands
);
