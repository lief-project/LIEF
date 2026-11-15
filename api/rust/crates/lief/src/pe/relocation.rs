//! This module includes the different structures related to the relocation process in a PE binary

use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::{declare_iterator, enum_from_int, generic};

/// Class which represents the *Base Relocation Block*
/// We usually find this structure in the `.reloc` section
pub struct Relocation<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Relocation>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl Relocation<'_> {
    /// The RVA for which the offset of the relocation entries is added
    pub fn virtual_address(&self) -> u32 {
        self.ptr.virtual_address()
    }

    /// The total number of bytes in the base relocation block.
    /// `block_size = sizeof(BaseRelocationBlock) + nb_of_relocs * sizeof(uint16_t = RelocationEntry)`
    pub fn block_size(&self) -> u32 {
        self.ptr.block_size()
    }
    /// Iterator over the Relocation [`Entry`]
    pub fn entries(&self) -> RelocationEntries<'_> {
        RelocationEntries::new(self.ptr.entries())
    }
}

impl std::fmt::Debug for Relocation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relocation")
            .field("virtual_address", &self.virtual_address())
            .field("block_size", &self.block_size())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_Relocation> for Relocation<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Relocation>) -> Self {
        Relocation {
            ptr,
            _owner: PhantomData,
        }
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    BaseType: u32 {
        ABS = 0x00000000,
        HIGH = 0x00000001,
        LOW = 0x00000002,
        HIGHLOW = 0x00000003,
        HIGHADJ = 0x00000004,
        MIPS_JMPADDR = 0x00000105,
        ARM_MOV32 = 0x00000205,
        RISCV_HI20 = 0x00000405,
        SECTION = 0x00000006,
        THUMB_MOV32 = 0x00000807,
        RISCV_LOW12I = 0x00001007,
        RISCV_LOW12S = 0x00002008,
        LOONARCH_MARK_LA = 0x00004008,
        MIPS_JMPADDR16 = 0x00000009,
        DIR64 = 0x0000000a,
        HIGH3ADJ = 0x0000000b,
    }
}
/// Class which represents an entry in the relocation table
///
/// It implements the [`generic::Relocation`] trait which provides additional functions
pub struct Entry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_RelocationEntry>,
    _owner: PhantomData<&'a ffi::PE_Relocation>,
}

impl generic::Relocation for Entry<'_> {
    fn as_generic(&self) -> &ffi::AbstractRelocation {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Entry<'_> {
    /// Offset relative to [`Relocation::virtual_address`] where the relocation occurs.
    pub fn position(&self) -> u64 {
        self.ptr.position()
    }

    /// Type of the relocation
    pub fn get_type(&self) -> BaseType {
        BaseType::from(self.ptr.get_type())
    }

    /// Raw data of the relocation:
    /// - The **high** 4 bits store the relocation type
    /// - The **low** 12 bits store the relocation offset
    pub fn data(&self) -> u16 {
        self.ptr.data()
    }
}

impl std::fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Relocation;
        f.debug_struct("RelocationEntry")
            .field("base", &base)
            .field("type", &self.get_type())
            .field("data", &self.data())
            .field("position", &self.position())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_RelocationEntry> for Entry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_RelocationEntry>) -> Self {
        Entry {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    RelocationEntries,
    Entry<'a>,
    ffi::PE_RelocationEntry,
    ffi::PE_Relocation,
    ffi::PE_Relocation_it_entries
);
declare_iterator!(
    Relocations,
    Relocation<'a>,
    ffi::PE_Relocation,
    ffi::PE_Binary,
    ffi::PE_Binary_it_relocations
);
