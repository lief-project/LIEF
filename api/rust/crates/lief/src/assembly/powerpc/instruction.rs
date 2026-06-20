use lief_ffi as ffi;

use super::Opcode;
use crate::assembly;
use crate::common::FromFFI;

use crate::assembly::powerpc;
use crate::declare_fwd_iterator;

/// This structure represents a PowerPC (ppc64/ppc32) instruction
pub struct Instruction {
    ptr: cxx::UniquePtr<ffi::asm_powerpc_Instruction>,
}

impl FromFFI<ffi::asm_powerpc_Instruction> for Instruction {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_powerpc_Instruction>) -> Self {
        Self { ptr }
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

    /// Return an iterator over the [`powerpc::Operands`] operands
    pub fn operands(&self) -> Operands<'_> {
        Operands::new(self.ptr.operands())
    }
}

declare_fwd_iterator!(
    Operands,
    powerpc::Operands,
    ffi::asm_Instruction,
    ffi::asm_powerpc_Operand,
    ffi::asm_powerpc_Instruction_it_operands
);
