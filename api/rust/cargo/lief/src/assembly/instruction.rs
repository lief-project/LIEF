//! Module related to assembly instructions

use lief_ffi as ffi;

use crate::to_slice;

use crate::common::FromFFI;

use super::aarch64;
use super::x86;
use super::arm;
use super::mips;
use super::powerpc;
use super::riscv;
use super::ebpf;

/// This trait is shared by all [`Instructions`] supported by LIEF
pub trait Instruction {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_Instruction;

    /// Address of the instruction
    fn address(&self) -> u64 {
        self.as_generic().address()
    }

    /// Size of the instruction in bytes
    fn size(&self) -> u64 {
        self.as_generic().size()
    }

    /// Raw bytes of the current instruction
    fn raw(&self) -> &[u8] {
        to_slice!(self.as_generic().raw());
    }

    /// Instruction mnemonic (e.g. `br`)
    fn mnemonic(&self) -> String {
        self.as_generic().mnemonic().to_string()
    }

    /// Representation of the current instruction in a pretty assembly way
    fn to_string(&self) -> String {
        self.as_generic().to_string().to_string()
    }

    /// True if the instruction is a call
    fn is_call(&self) -> bool {
        self.as_generic().is_call()
    }

    /// True if the instruction marks the end of a basic block
    fn is_terminator(&self) -> bool {
        self.as_generic().is_terminator()
    }

    /// True if the instruction is a branch
    fn is_branch(&self) -> bool {
        self.as_generic().is_branch()
    }

    /// True if the instruction is a syscall
    fn is_syscall(&self) -> bool {
        self.as_generic().is_syscall()
    }
}

/// All instruction variants supported by LIEF
pub enum Instructions {
    /// An AArch64 instruction
    AArch64(aarch64::Instruction),

    /// A x86/x86-64 instruction
    X86(x86::Instruction),

    /// An ARM/thumb instruction
    ARM(arm::Instruction),

    /// An eBPF instruction
    EBPF(ebpf::Instruction),

    /// A PowerPC (ppc64/ppc32) instruction
    PowerPC(powerpc::Instruction),

    /// A Mips (mips32/mips64) instruction
    Mips(mips::Instruction),

    /// A RISC-V (32 or 64 bit) instruction
    RiscV(riscv::Instruction),

    /// A generic instruction that doesn't have an extended structure
    Generic(Generic),
}

impl FromFFI<ffi::asm_Instruction> for Instructions {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_Instruction>) -> Self {
        unsafe {
           let inst_ref = ptr.as_ref().unwrap();
           if ffi::asm_aarch64_Instruction::classof(inst_ref) {
               let raw = {
                   type From = cxx::UniquePtr<ffi::asm_Instruction>;
                   type To   = cxx::UniquePtr<ffi::asm_aarch64_Instruction>;
                   std::mem::transmute::<From, To>(ptr)
               };
               return Instructions::AArch64(aarch64::Instruction::from_ffi(raw));
           }
           else if ffi::asm_x86_Instruction::classof(inst_ref) {
               let raw = {
                   type From = cxx::UniquePtr<ffi::asm_Instruction>;
                   type To   = cxx::UniquePtr<ffi::asm_x86_Instruction>;
                   std::mem::transmute::<From, To>(ptr)
               };
               return Instructions::X86(x86::Instruction::from_ffi(raw));
           }
           else if ffi::asm_arm_Instruction::classof(inst_ref) {
               let raw = {
                   type From = cxx::UniquePtr<ffi::asm_Instruction>;
                   type To   = cxx::UniquePtr<ffi::asm_arm_Instruction>;
                   std::mem::transmute::<From, To>(ptr)
               };
               return Instructions::ARM(arm::Instruction::from_ffi(raw));
           }
           else if ffi::asm_mips_Instruction::classof(inst_ref) {
               let raw = {
                   type From = cxx::UniquePtr<ffi::asm_Instruction>;
                   type To   = cxx::UniquePtr<ffi::asm_mips_Instruction>;
                   std::mem::transmute::<From, To>(ptr)
               };
               return Instructions::Mips(mips::Instruction::from_ffi(raw));
           }
           else if ffi::asm_powerpc_Instruction::classof(inst_ref) {
               let raw = {
                   type From = cxx::UniquePtr<ffi::asm_Instruction>;
                   type To   = cxx::UniquePtr<ffi::asm_powerpc_Instruction>;
                   std::mem::transmute::<From, To>(ptr)
               };
               return Instructions::PowerPC(powerpc::Instruction::from_ffi(raw));
           }
           else if ffi::asm_riscv_Instruction::classof(inst_ref) {
               let raw = {
                   type From = cxx::UniquePtr<ffi::asm_Instruction>;
                   type To   = cxx::UniquePtr<ffi::asm_riscv_Instruction>;
                   std::mem::transmute::<From, To>(ptr)
               };
               return Instructions::RiscV(riscv::Instruction::from_ffi(raw));
           }

           else if ffi::asm_ebpf_Instruction::classof(inst_ref) {
               let raw = {
                   type From = cxx::UniquePtr<ffi::asm_Instruction>;
                   type To   = cxx::UniquePtr<ffi::asm_ebpf_Instruction>;
                   std::mem::transmute::<From, To>(ptr)
               };
               return Instructions::EBPF(ebpf::Instruction::from_ffi(raw));
           }
           return Instructions::Generic(Generic::from_ffi(ptr));
        }
    }
}

impl Instruction for Instructions {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_Instruction {
        match &self {
            Instructions::Generic(inst) => {
                inst.as_generic()
            }
            Instructions::AArch64(inst) => {
                inst.as_generic()
            }
            Instructions::X86(inst) => {
                inst.as_generic()
            }
            Instructions::ARM(inst) => {
                inst.as_generic()
            }
            Instructions::Mips(inst) => {
                inst.as_generic()
            }
            Instructions::PowerPC(inst) => {
                inst.as_generic()
            }
            Instructions::EBPF(inst) => {
                inst.as_generic()
            }
            Instructions::RiscV(inst) => {
                inst.as_generic()
            }
        }
    }
}

/// Generic Instruction
pub struct Generic {
    ptr: cxx::UniquePtr<ffi::asm_Instruction>,
}

impl FromFFI<ffi::asm_Instruction> for Generic {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_Instruction>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Instruction for Generic {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_Instruction {
        self.ptr.as_ref().unwrap()
    }
}
