use lief_ffi as ffi;

use super::hash::{Sysv, Gnu};
use super::dynamic::DynamicEntries;
use super::header::Header;
use super::section::Sections;
use super::segment::Segments;
use super::symbol::{DynamicSymbols, ExportedSymbols, ImportedSymbols, SymtabSymbols};
use super::note::ItNotes;
use super::relocation::{PltGotRelocations, DynamicRelocations, ObjectRelocations, Relocations};
use super::symbol_versioning::{SymbolVersion, SymbolVersionDefinition, SymbolVersionRequirement};

use crate::generic;
use crate::declare_iterator;
use crate::common::{into_optional, FromFFI};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElfClass {
    Elf32,
    Elf64,
    Unknown,
}

impl ElfClass {
    const ELF_CLASS32: u32 = 1;
    const ELF_CLASS64: u32 = 2;

    pub fn from_value(value: u32) -> Self {
        match value {
            Self::ELF_CLASS32 => ElfClass::Elf32,
            Self::ELF_CLASS64 => ElfClass::Elf64,
            _ => ElfClass::Unknown,
        }
    }
}

pub struct Binary {
    ptr: cxx::UniquePtr<ffi::ELF_Binary>,
}

impl std::fmt::Debug for Binary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binary")
            .field("header", &self.header())
            .finish()
    }
}

impl FromFFI<ffi::ELF_Binary> for Binary {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::ELF_Binary>) -> Self {
        Self {
            ptr,
        }
    }
}

impl Binary {
    pub fn parse(path: &str) -> Self {
        let bin = ffi::ELF_Binary::parse(path);
        Binary::from_ffi(bin)
    }

    pub fn header(&self) -> Header {
        Header::from_ffi(self.ptr.header())
    }

    pub fn sysv_hash(&self) -> Option<Sysv> {
        into_optional(self.ptr.sysv_hash())
    }

    pub fn gnu_hash(&self) -> Option<Gnu> {
        into_optional(self.ptr.gnu_hash())
    }

    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    pub fn segments(&self) -> Segments {
        Segments::new(self.ptr.segments())
    }

    pub fn dynamic_entries(&self) -> DynamicEntries {
        DynamicEntries::new(self.ptr.dynamic_entries())
    }

    pub fn dynamic_symbols(&self) -> DynamicSymbols {
        DynamicSymbols::new(self.ptr.dynamic_symbols())
    }

    pub fn exported_symbols(&self) -> ExportedSymbols {
        ExportedSymbols::new(self.ptr.exported_symbols())
    }

    pub fn imported_symbols(&self) -> ImportedSymbols {
        ImportedSymbols::new(self.ptr.imported_symbols())
    }

    pub fn symtab_symbols(&self) -> SymtabSymbols {
        SymtabSymbols::new(self.ptr.symtab_symbols())
    }

    pub fn symbols_version(&self) -> SymbolsVersion {
        SymbolsVersion::new(self.ptr.symbols_version())
    }

    pub fn symbols_version_requirement(&self) -> SymbolsVersionRequirement {
        SymbolsVersionRequirement::new(self.ptr.symbols_version_requirement())
    }

    pub fn symbols_version_definition(&self) -> SymbolsVersionDefinition {
        SymbolsVersionDefinition::new(self.ptr.symbols_version_definition())
    }

    pub fn notes(&self) -> ItNotes {
        ItNotes::new(self.ptr.notes())
    }

    pub fn pltgot_relocations(&self) -> PltGotRelocations {
        PltGotRelocations::new(self.ptr.pltgot_relocations())
    }

    pub fn dynamic_relocations(&self) -> DynamicRelocations {
        DynamicRelocations::new(self.ptr.dynamic_relocations())
    }

    pub fn object_relocations(&self) -> ObjectRelocations {
        ObjectRelocations::new(self.ptr.object_relocations())
    }

    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }
}

impl generic::Binary for Binary {
    fn as_generic(&self) -> &ffi::AbstractBinary {
        self.ptr.as_ref().unwrap().as_ref()
    }
}


declare_iterator!(SymbolsVersion, SymbolVersion<'a>, ffi::ELF_SymbolVersion, ffi::ELF_Binary, ffi::ELF_Binary_it_symbols_version);
declare_iterator!(SymbolsVersionRequirement, SymbolVersionRequirement<'a>, ffi::ELF_SymbolVersionRequirement, ffi::ELF_Binary, ffi::ELF_Binary_it_symbols_version_requirement);
declare_iterator!(SymbolsVersionDefinition, SymbolVersionDefinition<'a>, ffi::ELF_SymbolVersionDefinition, ffi::ELF_Binary, ffi::ELF_Binary_it_symbols_version_definition);
