use lief_ffi as ffi;

use super::Opcode;
use crate::assembly;
use crate::common::FromFFI;

use crate::assembly::riscv;
use crate::declare_fwd_iterator;

/// This structure represents a RISC-V (32 or 64 bit) instruction
pub struct Instruction {
    ptr: cxx::UniquePtr<ffi::asm_riscv_Instruction>,
}

impl FromFFI<ffi::asm_riscv_Instruction> for Instruction {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_riscv_Instruction>) -> Self {
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

    /// Return an iterator over the [`riscv::Operands`] operands
    pub fn operands(&self) -> Operands<'_> {
        Operands::new(self.ptr.operands())
    }
}

declare_fwd_iterator!(
    Operands,
    riscv::Operands,
    ffi::asm_Instruction,
    ffi::asm_riscv_Operand,
    ffi::asm_riscv_Instruction_it_operands
);
