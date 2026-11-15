//! COFF relocation module

use super::{Section, Symbol};
use crate::common::{FromFFI, into_optional};
use crate::enum_from_int;
use crate::generic;
use std::marker::PhantomData;

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

enum_from_int! {
    #[allow(non_camel_case_types)]
    Type: u32 {
        I386_ABSOLUTE = 0x00020000,
        I386_DIR16 = 0x00020001,
        I386_REL16 = 0x00020002,
        I386_DIR32 = 0x00020006,
        I386_DIR32NB = 0x00020007,
        I386_SEG12 = 0x00020009,
        I386_SECTION = 0x0002000a,
        I386_SECREL = 0x0002000b,
        I386_TOKEN = 0x0002000c,
        I386_SECREL7 = 0x0002000d,
        I386_REL32 = 0x00020014,
        AMD64_ABSOLUTE = 0x00040000,
        AMD64_ADDR64 = 0x00040001,
        AMD64_ADDR32 = 0x00040002,
        AMD64_ADDR32NB = 0x00040003,
        AMD64_REL32 = 0x00040004,
        AMD64_REL32_1 = 0x00040005,
        AMD64_REL32_2 = 0x00040006,
        AMD64_REL32_3 = 0x00040007,
        AMD64_REL32_4 = 0x00040008,
        AMD64_REL32_5 = 0x00040009,
        AMD64_SECTION = 0x0004000a,
        AMD64_SECREL = 0x0004000b,
        AMD64_SECREL7 = 0x0004000c,
        AMD64_TOKEN = 0x0004000d,
        AMD64_SREL32 = 0x0004000e,
        AMD64_PAIR = 0x0004000f,
        AMD64_SSPAN32 = 0x00040010,
        ARM_ABSOLUTE = 0x00080000,
        ARM_ADDR32 = 0x00080001,
        ARM_ADDR32NB = 0x00080002,
        ARM_BRANCH24 = 0x00080003,
        ARM_BRANCH11 = 0x00080004,
        ARM_TOKEN = 0x00080005,
        ARM_BLX24 = 0x00080008,
        ARM_BLX11 = 0x00080009,
        ARM_REL32 = 0x0008000a,
        ARM_SECTION = 0x0008000e,
        ARM_SECREL = 0x0008000f,
        ARM_MOV32A = 0x00080010,
        ARM_MOV32T = 0x00080011,
        ARM_BRANCH20T = 0x00080012,
        ARM_BRANCH24T = 0x00080014,
        ARM_BLX23T = 0x00080015,
        ARM_PAIR = 0x00080016,
        ARM64_ABSOLUTE = 0x00100000,
        ARM64_ADDR32 = 0x00100001,
        ARM64_ADDR32NB = 0x00100002,
        ARM64_BRANCH26 = 0x00100003,
        ARM64_PAGEBASE_REL21 = 0x00100004,
        ARM64_REL21 = 0x00100005,
        ARM64_PAGEOFFSET_12A = 0x00100006,
        ARM64_PAGEOFFSET_12L = 0x00100007,
        ARM64_SECREL = 0x00100008,
        ARM64_SECREL_LOW12A = 0x00100009,
        ARM64_SECREL_HIGH12A = 0x0010000a,
        ARM64_SECREL_LOW12L = 0x0010000b,
        ARM64_TOKEN = 0x0010000c,
        ARM64_SECTION = 0x0010000d,
        ARM64_ADDR64 = 0x0010000e,
        ARM64_BRANCH19 = 0x0010000f,
        ARM64_BRANCH14 = 0x00100010,
        ARM64_REL32 = 0x00100011,
        MIPS_ABSOLUTE = 0x00200000,
        MIPS_REFHALF = 0x00200001,
        MIPS_REFWORD = 0x00200002,
        MIPS_JMPADDR = 0x00200003,
        MIPS_REFHI = 0x00200004,
        MIPS_REFLO = 0x00200005,
        MIPS_GPREL = 0x00200006,
        MIPS_LITERAL = 0x00200007,
        MIPS_SECTION = 0x0020000a,
        MIPS_SECREL = 0x0020000b,
        MIPS_SECRELLO = 0x0020000c,
        MIPS_SECRELHI = 0x0020000d,
        MIPS_JMPADDR16 = 0x00200010,
        MIPS_REFWORDNB = 0x00200022,
        MIPS_PAIR = 0x00200025,
    }
}
