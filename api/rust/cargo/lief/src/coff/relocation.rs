//! COFF relocation module

use std::marker::PhantomData;
use crate::common::{into_optional, FromFFI};
use crate::generic;
use super::{Section, Symbol};

use lief_ffi as ffi;

/// This class represents a COFF relocation
pub struct Relocation<'a> {
    ptr: cxx::UniquePtr<ffi::COFF_Relocation>,
    _owner: PhantomData<&'a ffi::COFF_Binary>,
}

impl FromFFI<ffi::COFF_Relocation> for Relocation<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::COFF_Relocation>) -> Self {
        Relocation {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl generic::Relocation for Relocation<'_> {
    fn as_generic(&self) -> &ffi::AbstractRelocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Relocation<'_> {
    /// Symbol index associated with this relocation
    pub fn symbol_idx(&self) -> u32 {
        self.ptr.symbol_idx()
    }

    /// Symbol associated with the relocation (if any)
    pub fn symbol(&self) -> Option<Symbol<'_>> {
        into_optional(self.ptr.symbol())
    }

    /// Type of the relocation
    pub fn get_type(&self) -> Type {
        Type::from(self.ptr.get_type())
    }

    /// Section in which the relocation takes place
    pub fn section(&self) -> Option<Section<'_>> {
        into_optional(self.ptr.section())
    }
}

impl std::fmt::Debug for Relocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Relocation;
        f.debug_struct("Relocation")
            .field("base", &base)
            .field("symbol_idx", &self.symbol_idx())
            .field("type", &self.get_type())
            .finish()
    }
}

impl std::fmt::Display for Relocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    I386_ABSOLUTE,
    I386_DIR16,
    I386_REL16,
    I386_DIR32,
    I386_DIR32NB,
    I386_SEG12,
    I386_SECTION,
    I386_SECREL,
    I386_TOKEN,
    I386_SECREL7,
    I386_REL32,
    AMD64_ABSOLUTE,
    AMD64_ADDR64,
    AMD64_ADDR32,
    AMD64_ADDR32NB,
    AMD64_REL32,
    AMD64_REL32_1,
    AMD64_REL32_2,
    AMD64_REL32_3,
    AMD64_REL32_4,
    AMD64_REL32_5,
    AMD64_SECTION,
    AMD64_SECREL,
    AMD64_SECREL7,
    AMD64_TOKEN,
    AMD64_SREL32,
    AMD64_PAIR,
    AMD64_SSPAN32,
    ARM_ABSOLUTE,
    ARM_ADDR32,
    ARM_ADDR32NB,
    ARM_BRANCH24,
    ARM_BRANCH11,
    ARM_TOKEN,
    ARM_BLX24,
    ARM_BLX11,
    ARM_REL32,
    ARM_SECTION,
    ARM_SECREL,
    ARM_MOV32A,
    ARM_MOV32T,
    ARM_BRANCH20T,
    ARM_BRANCH24T,
    ARM_BLX23T,
    ARM_PAIR,
    ARM64_ABSOLUTE,
    ARM64_ADDR32,
    ARM64_ADDR32NB,
    ARM64_BRANCH26,
    ARM64_PAGEBASE_REL21,
    ARM64_REL21,
    ARM64_PAGEOFFSET_12A,
    ARM64_PAGEOFFSET_12L,
    ARM64_SECREL,
    ARM64_SECREL_LOW12A,
    ARM64_SECREL_HIGH12A,
    ARM64_SECREL_LOW12L,
    ARM64_TOKEN,
    ARM64_SECTION,
    ARM64_ADDR64,
    ARM64_BRANCH19,
    ARM64_BRANCH14,
    ARM64_REL32,
    MIPS_ABSOLUTE,
    MIPS_REFHALF,
    MIPS_REFWORD,
    MIPS_JMPADDR,
    MIPS_REFHI,
    MIPS_REFLO,
    MIPS_GPREL,
    MIPS_LITERAL,
    MIPS_SECTION,
    MIPS_SECREL,
    MIPS_SECRELLO,
    MIPS_SECRELHI,
    MIPS_JMPADDR16,
    MIPS_REFWORDNB,
    MIPS_PAIR,
    UNKNOWN(u32),
}

impl From<u32> for Type {
    fn from(value: u32) -> Self {
        match value {
            0x00020000 => Type::I386_ABSOLUTE,
            0x00020001 => Type::I386_DIR16,
            0x00020002 => Type::I386_REL16,
            0x00020006 => Type::I386_DIR32,
            0x00020007 => Type::I386_DIR32NB,
            0x00020009 => Type::I386_SEG12,
            0x0002000a => Type::I386_SECTION,
            0x0002000b => Type::I386_SECREL,
            0x0002000c => Type::I386_TOKEN,
            0x0002000d => Type::I386_SECREL7,
            0x00020014 => Type::I386_REL32,
            0x00040000 => Type::AMD64_ABSOLUTE,
            0x00040001 => Type::AMD64_ADDR64,
            0x00040002 => Type::AMD64_ADDR32,
            0x00040003 => Type::AMD64_ADDR32NB,
            0x00040004 => Type::AMD64_REL32,
            0x00040005 => Type::AMD64_REL32_1,
            0x00040006 => Type::AMD64_REL32_2,
            0x00040007 => Type::AMD64_REL32_3,
            0x00040008 => Type::AMD64_REL32_4,
            0x00040009 => Type::AMD64_REL32_5,
            0x0004000a => Type::AMD64_SECTION,
            0x0004000b => Type::AMD64_SECREL,
            0x0004000c => Type::AMD64_SECREL7,
            0x0004000d => Type::AMD64_TOKEN,
            0x0004000e => Type::AMD64_SREL32,
            0x0004000f => Type::AMD64_PAIR,
            0x00040010 => Type::AMD64_SSPAN32,
            0x00080000 => Type::ARM_ABSOLUTE,
            0x00080001 => Type::ARM_ADDR32,
            0x00080002 => Type::ARM_ADDR32NB,
            0x00080003 => Type::ARM_BRANCH24,
            0x00080004 => Type::ARM_BRANCH11,
            0x00080005 => Type::ARM_TOKEN,
            0x00080008 => Type::ARM_BLX24,
            0x00080009 => Type::ARM_BLX11,
            0x0008000a => Type::ARM_REL32,
            0x0008000e => Type::ARM_SECTION,
            0x0008000f => Type::ARM_SECREL,
            0x00080010 => Type::ARM_MOV32A,
            0x00080011 => Type::ARM_MOV32T,
            0x00080012 => Type::ARM_BRANCH20T,
            0x00080014 => Type::ARM_BRANCH24T,
            0x00080015 => Type::ARM_BLX23T,
            0x00080016 => Type::ARM_PAIR,
            0x00100000 => Type::ARM64_ABSOLUTE,
            0x00100001 => Type::ARM64_ADDR32,
            0x00100002 => Type::ARM64_ADDR32NB,
            0x00100003 => Type::ARM64_BRANCH26,
            0x00100004 => Type::ARM64_PAGEBASE_REL21,
            0x00100005 => Type::ARM64_REL21,
            0x00100006 => Type::ARM64_PAGEOFFSET_12A,
            0x00100007 => Type::ARM64_PAGEOFFSET_12L,
            0x00100008 => Type::ARM64_SECREL,
            0x00100009 => Type::ARM64_SECREL_LOW12A,
            0x0010000a => Type::ARM64_SECREL_HIGH12A,
            0x0010000b => Type::ARM64_SECREL_LOW12L,
            0x0010000c => Type::ARM64_TOKEN,
            0x0010000d => Type::ARM64_SECTION,
            0x0010000e => Type::ARM64_ADDR64,
            0x0010000f => Type::ARM64_BRANCH19,
            0x00100010 => Type::ARM64_BRANCH14,
            0x00100011 => Type::ARM64_REL32,
            0x00200000 => Type::MIPS_ABSOLUTE,
            0x00200001 => Type::MIPS_REFHALF,
            0x00200002 => Type::MIPS_REFWORD,
            0x00200003 => Type::MIPS_JMPADDR,
            0x00200004 => Type::MIPS_REFHI,
            0x00200005 => Type::MIPS_REFLO,
            0x00200006 => Type::MIPS_GPREL,
            0x00200007 => Type::MIPS_LITERAL,
            0x0020000a => Type::MIPS_SECTION,
            0x0020000b => Type::MIPS_SECREL,
            0x0020000c => Type::MIPS_SECRELLO,
            0x0020000d => Type::MIPS_SECRELHI,
            0x00200010 => Type::MIPS_JMPADDR16,
            0x00200022 => Type::MIPS_REFWORDNB,
            0x00200025 => Type::MIPS_PAIR,
            _ => Type::UNKNOWN(value),

        }
    }
}

impl From<Type> for u32 {
    fn from(value: Type) -> u32 {
        match value {
            Type::I386_ABSOLUTE => 0x00020000,
            Type::I386_DIR16 => 0x00020001,
            Type::I386_REL16 => 0x00020002,
            Type::I386_DIR32 => 0x00020006,
            Type::I386_DIR32NB => 0x00020007,
            Type::I386_SEG12 => 0x00020009,
            Type::I386_SECTION => 0x0002000a,
            Type::I386_SECREL => 0x0002000b,
            Type::I386_TOKEN => 0x0002000c,
            Type::I386_SECREL7 => 0x0002000d,
            Type::I386_REL32 => 0x00020014,
            Type::AMD64_ABSOLUTE => 0x00040000,
            Type::AMD64_ADDR64 => 0x00040001,
            Type::AMD64_ADDR32 => 0x00040002,
            Type::AMD64_ADDR32NB => 0x00040003,
            Type::AMD64_REL32 => 0x00040004,
            Type::AMD64_REL32_1 => 0x00040005,
            Type::AMD64_REL32_2 => 0x00040006,
            Type::AMD64_REL32_3 => 0x00040007,
            Type::AMD64_REL32_4 => 0x00040008,
            Type::AMD64_REL32_5 => 0x00040009,
            Type::AMD64_SECTION => 0x0004000a,
            Type::AMD64_SECREL => 0x0004000b,
            Type::AMD64_SECREL7 => 0x0004000c,
            Type::AMD64_TOKEN => 0x0004000d,
            Type::AMD64_SREL32 => 0x0004000e,
            Type::AMD64_PAIR => 0x0004000f,
            Type::AMD64_SSPAN32 => 0x00040010,
            Type::ARM_ABSOLUTE => 0x00080000,
            Type::ARM_ADDR32 => 0x00080001,
            Type::ARM_ADDR32NB => 0x00080002,
            Type::ARM_BRANCH24 => 0x00080003,
            Type::ARM_BRANCH11 => 0x00080004,
            Type::ARM_TOKEN => 0x00080005,
            Type::ARM_BLX24 => 0x00080008,
            Type::ARM_BLX11 => 0x00080009,
            Type::ARM_REL32 => 0x0008000a,
            Type::ARM_SECTION => 0x0008000e,
            Type::ARM_SECREL => 0x0008000f,
            Type::ARM_MOV32A => 0x00080010,
            Type::ARM_MOV32T => 0x00080011,
            Type::ARM_BRANCH20T => 0x00080012,
            Type::ARM_BRANCH24T => 0x00080014,
            Type::ARM_BLX23T => 0x00080015,
            Type::ARM_PAIR => 0x00080016,
            Type::ARM64_ABSOLUTE => 0x00100000,
            Type::ARM64_ADDR32 => 0x00100001,
            Type::ARM64_ADDR32NB => 0x00100002,
            Type::ARM64_BRANCH26 => 0x00100003,
            Type::ARM64_PAGEBASE_REL21 => 0x00100004,
            Type::ARM64_REL21 => 0x00100005,
            Type::ARM64_PAGEOFFSET_12A => 0x00100006,
            Type::ARM64_PAGEOFFSET_12L => 0x00100007,
            Type::ARM64_SECREL => 0x00100008,
            Type::ARM64_SECREL_LOW12A => 0x00100009,
            Type::ARM64_SECREL_HIGH12A => 0x0010000a,
            Type::ARM64_SECREL_LOW12L => 0x0010000b,
            Type::ARM64_TOKEN => 0x0010000c,
            Type::ARM64_SECTION => 0x0010000d,
            Type::ARM64_ADDR64 => 0x0010000e,
            Type::ARM64_BRANCH19 => 0x0010000f,
            Type::ARM64_BRANCH14 => 0x00100010,
            Type::ARM64_REL32 => 0x00100011,
            Type::MIPS_ABSOLUTE => 0x00200000,
            Type::MIPS_REFHALF => 0x00200001,
            Type::MIPS_REFWORD => 0x00200002,
            Type::MIPS_JMPADDR => 0x00200003,
            Type::MIPS_REFHI => 0x00200004,
            Type::MIPS_REFLO => 0x00200005,
            Type::MIPS_GPREL => 0x00200006,
            Type::MIPS_LITERAL => 0x00200007,
            Type::MIPS_SECTION => 0x0020000a,
            Type::MIPS_SECREL => 0x0020000b,
            Type::MIPS_SECRELLO => 0x0020000c,
            Type::MIPS_SECRELHI => 0x0020000d,
            Type::MIPS_JMPADDR16 => 0x00200010,
            Type::MIPS_REFWORDNB => 0x00200022,
            Type::MIPS_PAIR => 0x00200025,
            Type::UNKNOWN(value) => value,

        }
    }
}

