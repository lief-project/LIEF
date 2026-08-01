use lief_ffi as ffi;

use super::Opcode;
use crate::assembly;
use crate::common::{FromFFI, into_optional};

use crate::assembly::x86;
use crate::declare_fwd_iterator;

/// This structure represents a x86/x86-64 instruction
pub struct Instruction {
    ptr: cxx::UniquePtr<ffi::asm_x86_Instruction>,
}

impl FromFFI<ffi::asm_x86_Instruction> for Instruction {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_x86_Instruction>) -> Self {
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

    /// Return an iterator over the [`x86::Operands`] operands
    pub fn operands(&self) -> Operands<'_> {
        Operands::new(self.ptr.operands())
    }

    /// True if this instruction has a `LOCK` prefix
    pub fn has_lock_prefix(&self) -> bool {
        self.ptr.has_lock_prefix()
    }

    /// True if the `LOCK` prefix is architecturally valid on this instruction
    pub fn is_lockable(&self) -> bool {
        self.ptr.is_lockable()
    }

    /// True if this instruction executes as an atomic read-modify-write
    pub fn is_atomic(&self) -> bool {
        self.ptr.is_atomic()
    }

    /// Re-encoded copy of this instruction with a `LOCK` prefix added.
    ///
    /// If the instruction already has a `LOCK` prefix, it returns a plain copy.
    pub fn lock(&self) -> Option<Instruction> {
        into_optional(self.ptr.lock())
    }

    /// Re-encoded copy of this instruction with the `LOCK` prefix removed.
    ///
    /// If the instruction does not have a `LOCK` prefix, it returns a plain
    /// copy or `None` if the `LOCK` semantic can't be removed.
    pub fn unlock(&self) -> Option<Instruction> {
        into_optional(self.ptr.unlock())
    }
}

declare_fwd_iterator!(
    Operands,
    x86::Operands,
    ffi::asm_Instruction,
    ffi::asm_x86_Operand,
    ffi::asm_x86_Instruction_it_operands
);
