use lief_ffi as ffi;

use crate::to_slice;

use crate::common::FromFFI;

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
}

pub enum Instructions {
    Generic(Generic),
}

impl FromFFI<ffi::asm_Instruction> for Instructions {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::asm_Instruction>) -> Self {
        Instructions::Generic(Generic::from_ffi(ptr))
    }
}


impl Instruction for Instructions {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::asm_Instruction {
        match &self {
            Instructions::Generic(cmd) => {
                cmd.as_generic()
            }
        }
    }
}

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
