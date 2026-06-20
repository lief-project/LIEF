use lief_ffi as ffi;

use super::Opcode;
use crate::assembly;
use crate::common::FromFFI;

use crate::assembly::ebpf;
use crate::declare_fwd_iterator;

/// This structure represents an eBPF instruction
pub struct Instruction {
    ptr: cxx::UniquePtr<ffi::asm_ebpf_Instruction>,
}

impl FromFFI<ffi::asm_ebpf_Instruction> for Instruction {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_ebpf_Instruction>) -> Self {
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

    /// Return an iterator over the [`ebpf::Operands`] operands
    pub fn operands(&self) -> Operands<'_> {
        Operands::new(self.ptr.operands())
    }
}

declare_fwd_iterator!(
    Operands,
    ebpf::Operands,
    ffi::asm_Instruction,
    ffi::asm_ebpf_Operand,
    ffi::asm_ebpf_Instruction_it_operands
);
