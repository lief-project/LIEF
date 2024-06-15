//! This module includes the different structures related to the relocation process in a PE binary

use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::{declare_iterator, generic};

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
    pub fn entries(&self) -> RelocationEntries {
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

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum BaseType {
    ABS,
    HIGH,
    LOW,
    HIGHLOW,
    HIGHADJ,
    MIPS_JMPADDR,
    ARM_MOV32A,
    ARM_MOV32,
    RISCV_HI20,
    SECTION,
    REL,
    ARM_MOV32T,
    THUMB_MOV32,
    RISCV_LOW12I,
    RISCV_LOW12S,
    IA64_IMM64,
    MIPS_JMPADDR16,
    DIR64,
    HIGH3ADJ,
    UNKNOWN(u32),
}

impl BaseType {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000000 => BaseType::ABS,
            0x00000001 => BaseType::HIGH,
            0x00000002 => BaseType::LOW,
            0x00000003 => BaseType::HIGHLOW,
            0x00000004 => BaseType::HIGHADJ,
            0x00000005 => BaseType::MIPS_JMPADDR,
            0x00000106 => BaseType::ARM_MOV32A,
            0x00000107 => BaseType::ARM_MOV32,
            0x00000108 => BaseType::RISCV_HI20,
            0x00000006 => BaseType::SECTION,
            0x00000007 => BaseType::REL,
            0x00000208 => BaseType::ARM_MOV32T,
            0x00000209 => BaseType::THUMB_MOV32,
            0x0000020a => BaseType::RISCV_LOW12I,
            0x00000008 => BaseType::RISCV_LOW12S,
            0x00000009 => BaseType::IA64_IMM64,
            0x00000309 => BaseType::MIPS_JMPADDR16,
            0x0000000a => BaseType::DIR64,
            0x0000000b => BaseType::HIGH3ADJ,
            _ => BaseType::UNKNOWN(value),
        }
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
        BaseType::from_value(self.ptr.get_type())
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
