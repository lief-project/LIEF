use std::mem::size_of;
use std::path::Path;
use std::pin::Pin;

use num_traits::{cast, Num};

use lief_ffi as ffi;

use super::builder::Config;
use super::dynamic::{self, DynamicEntries, DynamicEntry, Library};
use super::hash::{Gnu, Sysv};
use super::header::Header;
use super::note::ItNotes;
use super::relocation::{
    DynamicRelocations, ObjectRelocations, PltGotRelocations, Relocation, Relocations,
};
use super::section::{Section, Sections};
use super::segment::Segments;
use super::symbol::{DynamicSymbols, ExportedSymbols, ImportedSymbols, SymtabSymbols};
use super::symbol_versioning::{SymbolVersion, SymbolVersionDefinition, SymbolVersionRequirement};
use super::{Segment, Symbol};
use crate::Error;

use crate::common::{into_optional, FromFFI};
use crate::generic;
use crate::{declare_iterator, to_conv_result, to_result, to_slice};

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

/// This is the main interface to read and write ELF binary attributes.
///
/// Note that this structure implements the [`generic::Binary`] trait from which other generic
/// functions are exposed
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
        Self { ptr }
    }
}

impl Binary {
    /// Create a [`Binary`] from the given file path
    pub fn parse(path: &str) -> Option<Self> {
        let bin = ffi::ELF_Binary::parse(path);
        if bin.is_null() {
            return None;
        }
        Some(Binary::from_ffi(bin))
    }

    /// Return the main ELF header
    pub fn header(&self) -> Header {
        Header::from_ffi(self.ptr.header())
    }

    /// Return the size taken by the binary when loaded (virtual size)
    pub fn virtual_size(&self) -> u64 {
        self.ptr.virtual_size()
    }

    /// Return the path to the ELF interpreter that is used to process the ELF information
    /// once loaded by the kernel
    pub fn interpreter(&self) -> String {
        self.ptr.interpreter().to_string()
    }

    /// Return sysv-hash information (if present)
    pub fn sysv_hash(&self) -> Option<Sysv> {
        into_optional(self.ptr.sysv_hash())
    }

    /// Return GNU Hash info (if present)
    pub fn gnu_hash(&self) -> Option<Gnu> {
        into_optional(self.ptr.gnu_hash())
    }

    /// Return an iterator over the [`crate::elf::Section`] of the binary
    pub fn sections(&self) -> Sections {
        Sections::new(self.ptr.sections())
    }

    /// Return an iterator over the [`crate::elf::Segment`] of the binary
    pub fn segments(&self) -> Segments {
        Segments::new(self.ptr.segments())
    }

    /// Return an iterator over the [`crate::elf::DynamicEntries`] of the binary
    pub fn dynamic_entries(&self) -> DynamicEntries {
        DynamicEntries::new(self.ptr.dynamic_entries())
    }

    /// Remove **all** dynamic entries with the given tag
    pub fn remove_dynamic_entries_by_tag(&mut self, tag: dynamic::Tag) {
        self.ptr.as_mut().unwrap().remove_dynamic_entries_by_tag(tag.into())
    }

    /// Add the given dynamic entry and return the new entry
    pub fn add_dynamic_entry(&mut self, entry: &dynamic::Entries) -> dynamic::Entries {
        dynamic::Entries::from_ffi(self.ptr.as_mut().unwrap().add_dynamic_entry(entry.as_base()))
    }

    /// Return an iterator over the dynamic [`crate::elf::Symbol`] of the binary
    pub fn dynamic_symbols(&self) -> DynamicSymbols {
        DynamicSymbols::new(self.ptr.dynamic_symbols())
    }

    /// Return an iterator over the **exported** [`crate::elf::Symbol`] of the binary
    pub fn exported_symbols(&self) -> ExportedSymbols {
        ExportedSymbols::new(self.ptr.exported_symbols())
    }

    /// Return an iterator over the **imported** [`crate::elf::Symbol`] of the binary
    pub fn imported_symbols(&self) -> ImportedSymbols {
        ImportedSymbols::new(self.ptr.imported_symbols())
    }

    /// Return an iterator over the symtab-debug [`crate::elf::Symbol`] of the binary
    pub fn symtab_symbols(&self) -> SymtabSymbols {
        SymtabSymbols::new(self.ptr.symtab_symbols())
    }

    /// Return an iterator over the  [`crate::elf::SymbolVersion`] of the binary
    pub fn symbols_version(&self) -> SymbolsVersion {
        SymbolsVersion::new(self.ptr.symbols_version())
    }

    /// Return an iterator over the  [`crate::elf::SymbolVersionRequirement`] of the binary
    pub fn symbols_version_requirement(&self) -> SymbolsVersionRequirement {
        SymbolsVersionRequirement::new(self.ptr.symbols_version_requirement())
    }

    /// Return an iterator over the  [`crate::elf::SymbolVersionDefinition`] of the binary
    pub fn symbols_version_definition(&self) -> SymbolsVersionDefinition {
        SymbolsVersionDefinition::new(self.ptr.symbols_version_definition())
    }

    /// Return an iterator over the  [`crate::elf::Notes`] of the binary
    pub fn notes(&self) -> ItNotes {
        ItNotes::new(self.ptr.notes())
    }

    /// Return an iterator over the `.plt.got` [`crate::elf::Relocation`] of the binary
    pub fn pltgot_relocations(&self) -> PltGotRelocations {
        PltGotRelocations::new(self.ptr.pltgot_relocations())
    }

    /// Return an iterator over the regular [`crate::elf::Relocation`] of the binary
    pub fn dynamic_relocations(&self) -> DynamicRelocations {
        DynamicRelocations::new(self.ptr.dynamic_relocations())
    }

    /// Return an iterator over the object-file (`.o`) [`crate::elf::Relocation`]
    pub fn object_relocations(&self) -> ObjectRelocations {
        ObjectRelocations::new(self.ptr.object_relocations())
    }

    /// Return an iterator over **all** [`crate::elf::Relocation`] of the binary
    pub fn relocations(&self) -> Relocations {
        Relocations::new(self.ptr.relocations())
    }

    /// Try to find the ELF section with the given name
    pub fn section_by_name(&self, name: &str) -> Option<Section> {
        into_optional(self.ptr.section_by_name(name))
    }

    /// Try to find the ELF relocation that takes place at the given address
    pub fn relocation_by_addr(&self, address: u64) -> Option<Relocation> {
        into_optional(self.ptr.relocation_by_addr(address))
    }

    /// Try to find the `.plt.got` relocation for the given symbol name
    pub fn relocation_for_symbol(&self, sym_name: &str) -> Option<Relocation> {
        into_optional(self.ptr.relocation_for_symbol(sym_name))
    }

    /// Try to find the symbol with the given name in the dynamic `.dynsym` table
    pub fn dynamic_symbol_by_name(&self, sym_name: &str) -> Option<Symbol> {
        into_optional(self.ptr.get_dynamic_symbol(sym_name))
    }

    /// Try to find the symbol with the given name in the debug `.symtab` table
    pub fn symtab_symbol_by_name(&self, sym_name: &str) -> Option<Symbol> {
        into_optional(self.ptr.get_symtab_symbol(sym_name))
    }

    /// Try to find the library (`DT_NEEDED`) with the given name
    pub fn get_library(&self, name: &str) -> Option<dynamic::Library> {
        into_optional(self.ptr.get_library(name))
    }

    /// Try to find the section that encompasses the given offset. `skip_nobits` can be used
    /// to include (or not) the `SHT_NOTBIT` sections
    pub fn section_from_offset(&self, offset: u64, skip_nobits: bool) -> Option<Section> {
        into_optional(self.ptr.section_from_offset(offset, skip_nobits))
    }

    /// Try to find the section that encompasses the given virtual address. `skip_nobits` can be used
    /// to include (or not) the `SHT_NOTBIT` sections
    pub fn section_from_virtual_address(&self, address: u64, skip_nobits: bool) -> Option<Section> {
        into_optional(self.ptr.section_from_virtual_address(address, skip_nobits))
    }

    /// Try to find the segment that encompasses the given virtual address
    pub fn segment_from_virtual_address(&self, address: u64) -> Option<Segment> {
        into_optional(self.ptr.segment_from_virtual_address(address))
    }

    /// Try to find the segment that encompasses the given offset
    pub fn segment_from_offset(&self, offset: u64) -> Option<Segment> {
        into_optional(self.ptr.segment_from_offset(offset))
    }

    /// Get a slice of the content at the given address.
    pub fn content_from_virtual_address(&self, address: u64, size: u64) -> &[u8] {
        to_slice!(self.ptr.get_content_from_virtual_address(address, size));
    }

    /// Convert the given virtual address into an offset
    pub fn virtual_address_to_offset(&self, address: u64) -> Result<u64, Error> {
        to_result!(ffi::ELF_Binary::virtual_address_to_offset, &self, address);
    }

    /// Return the array defined by the given tag (e.g.
    /// [`dynamic::Tag::INIT_ARRAY`]) with relocations applied (if any)
    pub fn get_relocated_dynamic_array(&self, tag: dynamic::Tag) -> Vec<u64> {
        Vec::from(
            self.ptr
                .get_relocated_dynamic_array(u64::from(tag))
                .as_slice(),
        )
    }

    /// True if the current binary is targeting Android
    pub fn is_targeting_android(&self) -> bool {
        self.ptr.is_targeting_android()
    }

    /// Get the integer value at the given virtual address
    pub fn get_int_from_virtual_address<T>(&self, addr: u64) -> Result<T, Error>
    where
        T: Num + cast::FromPrimitive + cast::ToPrimitive,
    {
        // Can't be in the generic trait because of:
        //   > for a trait to be "object safe" it needs to allow building a vtable to allow the call
        //   > to be resolvable dynamically; for more information visit
        //   > https://doc.rust-lang.org/reference/items/traits.html#object-safety
        if size_of::<T>() == size_of::<u8>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u8,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u8(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u16>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u16,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u16(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u32>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u32,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u32(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u64>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u64,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u64(value).expect(format!("Can't cast value: {}", value).as_str())
                },
                addr
            );
        }

        Err(Error::NotSupported)
    }

    /// Write back the current ELF binary into the file specified in parameter
    pub fn write(&mut self, output: &Path) {
        self.ptr.as_mut().unwrap().write(output.to_str().unwrap());
    }

    /// Write back the current ELF binary into the file specified in parameter with the
    /// configuration provided in the second parameter.
    pub fn write_with_config(&mut self, output: &Path, config: Config) {
        self.ptr
            .as_mut()
            .unwrap()
            .write_with_config(output.to_str().unwrap(), config.to_ffi());
    }

    /// Add a library as dependency
    pub fn add_library<'a>(&'a mut self, library: &str) -> Library<'a> {
        Library::from_ffi(self.ptr.as_mut().unwrap().add_library(library))
    }

    pub fn functions(&self) -> generic::Functions {
        generic::Functions::new(self.ptr.functions())
    }
}

impl generic::Binary for Binary {
    fn as_generic(&self) -> &ffi::AbstractBinary {
        self.ptr.as_ref().unwrap().as_ref()
    }

    fn as_pin_mut_generic(&mut self) -> Pin<&mut ffi::AbstractBinary> {
        unsafe {
            Pin::new_unchecked({
                (self.ptr.as_ref().unwrap().as_ref() as *const ffi::AbstractBinary
                    as *mut ffi::AbstractBinary)
                    .as_mut()
                    .unwrap()
            })
        }
    }
}

declare_iterator!(
    SymbolsVersion,
    SymbolVersion<'a>,
    ffi::ELF_SymbolVersion,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_symbols_version
);
declare_iterator!(
    SymbolsVersionRequirement,
    SymbolVersionRequirement<'a>,
    ffi::ELF_SymbolVersionRequirement,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_symbols_version_requirement
);
declare_iterator!(
    SymbolsVersionDefinition,
    SymbolVersionDefinition<'a>,
    ffi::ELF_SymbolVersionDefinition,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_symbols_version_definition
);
