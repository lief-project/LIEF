use std::mem::size_of;
use std::path::Path;
use std::pin::Pin;

use num_traits::{cast, Num};

use lief_ffi as ffi;

use super::builder::Config;
use super::dynamic::{self, DynamicEntries, Library};
use super::hash::{Gnu, Sysv};
use super::header::Header;
use super::note::ItNotes;
use super::parser_config::Config as ParserConfig;
use super::relocation::{
    DynamicRelocations, ObjectRelocations, PltGotRelocations, Relocation, Relocations,
};
use super::section::{Section, Sections};
use super::segment::{self, Segments};
use super::symbol::{DynamicSymbols, ExportedSymbols, ImportedSymbols, SymtabSymbols};
use super::symbol_versioning::{SymbolVersion, SymbolVersionDefinition, SymbolVersionRequirement};
use super::{Segment, Symbol};
use crate::elf::dynamic::DynamicEntry;
use crate::Error;

use crate::common::{into_optional, FromFFI, AsFFI};
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


/// Strategy used for relocating the PHDR table
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum PhdrReloc {
    /// Let LIEF choose the best strategy
    AUTO,
    /// Shift content after the PHDR table (PIE binaries only)
    PIE_SHIFT,
    /// Relocate the PHDR after the first BSS-like segment
    BSS_END,
    /// Relocate at the end of the binary
    BINARY_END,
    /// Relocate between two LOAD segments
    SEGMENT_GAP,
    UNKNOWN(u32),
}

impl From<u32> for PhdrReloc {
    fn from(value: u32) -> Self {
        match value {
            0 => PhdrReloc::AUTO,
            1 => PhdrReloc::PIE_SHIFT,
            2 => PhdrReloc::BSS_END,
            3 => PhdrReloc::BINARY_END,
            4 => PhdrReloc::SEGMENT_GAP,
            _ => PhdrReloc::UNKNOWN(value),
        }
    }
}

impl From<PhdrReloc> for u32 {
    fn from(value: PhdrReloc) -> u32 {
        match value {
            PhdrReloc::AUTO => 0,
            PhdrReloc::PIE_SHIFT => 1,
            PhdrReloc::BSS_END => 2,
            PhdrReloc::BINARY_END => 3,
            PhdrReloc::SEGMENT_GAP => 4,
            PhdrReloc::UNKNOWN(v) => v,
        }
    }
}

/// Strategy for inserting a new section
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SecInsertPos {
    /// Let LIEF choose the best strategy
    AUTO,
    /// Insert after the last segment offset, before debug info
    POST_SEGMENT,
    /// Insert after the last section offset, at binary end
    POST_SECTION,
    UNKNOWN(u32),
}

impl From<u32> for SecInsertPos {
    fn from(value: u32) -> Self {
        match value {
            0 => SecInsertPos::AUTO,
            1 => SecInsertPos::POST_SEGMENT,
            2 => SecInsertPos::POST_SECTION,
            _ => SecInsertPos::UNKNOWN(value),
        }
    }
}

impl From<SecInsertPos> for u32 {
    fn from(value: SecInsertPos) -> u32 {
        match value {
            SecInsertPos::AUTO => 0,
            SecInsertPos::POST_SEGMENT => 1,
            SecInsertPos::POST_SECTION => 2,
            SecInsertPos::UNKNOWN(v) => v,
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
    pub fn parse<P: AsRef<Path>>(path: P) -> Option<Self> {
        let bin = ffi::ELF_Binary::parse(path.as_ref().to_str().unwrap());
        if bin.is_null() {
            return None;
        }
        Some(Binary::from_ffi(bin))
    }

    /// Parse from a string file path and with a provided configuration
    pub fn parse_with_config<P: AsRef<Path>>(path: P, config: &ParserConfig) -> Option<Self> {
        let ffi_config = config.to_ffi();
        let ffi = ffi::ELF_Binary::parse_with_config(path.as_ref().to_str().unwrap(), &ffi_config);
        if ffi.is_null() {
            return None;
        }
        Some(Binary::from_ffi(ffi))
    }

    /// Return the main ELF header
    pub fn header(&self) -> Header<'_> {
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
    pub fn sysv_hash(&self) -> Option<Sysv<'_>> {
        into_optional(self.ptr.sysv_hash())
    }

    /// Return GNU Hash info (if present)
    pub fn gnu_hash(&self) -> Option<Gnu<'_>> {
        into_optional(self.ptr.gnu_hash())
    }

    /// Return an iterator over the [`crate::elf::Section`] of the binary
    pub fn sections(&self) -> Sections<'_> {
        Sections::new(self.ptr.sections())
    }

    /// Return an iterator over the [`crate::elf::Segment`] of the binary
    pub fn segments(&self) -> Segments<'_> {
        Segments::new(self.ptr.segments())
    }

    /// Return an iterator over the [`crate::elf::DynamicEntries`] of the binary
    pub fn dynamic_entries(&self) -> DynamicEntries<'_> {
        DynamicEntries::new(self.ptr.dynamic_entries())
    }

    /// Remove **all** dynamic entries with the given tag
    pub fn remove_dynamic_entries_by_tag(&mut self, tag: dynamic::Tag) {
        self.ptr
            .as_mut()
            .unwrap()
            .remove_dynamic_entries_by_tag(tag.into())
    }

    /// Add the given dynamic entry and return the new entry
    pub fn add_dynamic_entry(&mut self, entry: &dyn dynamic::DynamicEntry) -> dynamic::Entries<'_> {
        dynamic::Entries::from_ffi(
            self.ptr
                .as_mut()
                .unwrap()
                .add_dynamic_entry(entry.as_base()),
        )
    }

    /// Return an iterator over the dynamic [`crate::elf::Symbol`] of the binary
    pub fn dynamic_symbols(&self) -> DynamicSymbols<'_> {
        DynamicSymbols::new(self.ptr.dynamic_symbols())
    }

    /// Return an iterator over the **exported** [`crate::elf::Symbol`] of the binary
    pub fn exported_symbols(&self) -> ExportedSymbols<'_> {
        ExportedSymbols::new(self.ptr.exported_symbols())
    }

    /// Return an iterator over the **imported** [`crate::elf::Symbol`] of the binary
    pub fn imported_symbols(&self) -> ImportedSymbols<'_> {
        ImportedSymbols::new(self.ptr.imported_symbols())
    }

    /// Return an iterator over the symtab-debug [`crate::elf::Symbol`] of the binary
    pub fn symtab_symbols(&self) -> SymtabSymbols<'_> {
        SymtabSymbols::new(self.ptr.symtab_symbols())
    }

    /// Return an iterator over the  [`crate::elf::SymbolVersion`] of the binary
    pub fn symbols_version(&self) -> SymbolsVersion<'_> {
        SymbolsVersion::new(self.ptr.symbols_version())
    }

    /// Return an iterator over the  [`crate::elf::SymbolVersionRequirement`] of the binary
    pub fn symbols_version_requirement(&self) -> SymbolsVersionRequirement<'_> {
        SymbolsVersionRequirement::new(self.ptr.symbols_version_requirement())
    }

    /// Return an iterator over the  [`crate::elf::SymbolVersionDefinition`] of the binary
    pub fn symbols_version_definition(&self) -> SymbolsVersionDefinition<'_> {
        SymbolsVersionDefinition::new(self.ptr.symbols_version_definition())
    }

    /// Return an iterator over the  [`crate::elf::Notes`] of the binary
    pub fn notes(&self) -> ItNotes<'_> {
        ItNotes::new(self.ptr.notes())
    }

    /// Return an iterator over the `.plt.got` [`crate::elf::Relocation`] of the binary
    pub fn pltgot_relocations(&self) -> PltGotRelocations<'_> {
        PltGotRelocations::new(self.ptr.pltgot_relocations())
    }

    /// Return an iterator over the regular [`crate::elf::Relocation`] of the binary
    pub fn dynamic_relocations(&self) -> DynamicRelocations<'_> {
        DynamicRelocations::new(self.ptr.dynamic_relocations())
    }

    /// Return an iterator over the object-file (`.o`) [`crate::elf::Relocation`]
    pub fn object_relocations(&self) -> ObjectRelocations<'_> {
        ObjectRelocations::new(self.ptr.object_relocations())
    }

    /// Return an iterator over **all** [`crate::elf::Relocation`] of the binary
    pub fn relocations(&self) -> Relocations<'_> {
        Relocations::new(self.ptr.relocations())
    }

    /// Try to find the ELF section with the given name
    pub fn section_by_name(&self, name: &str) -> Option<Section<'_>> {
        into_optional(self.ptr.section_by_name(name))
    }

    /// Try to find the ELF relocation that takes place at the given address
    pub fn relocation_by_addr(&self, address: u64) -> Option<Relocation<'_>> {
        into_optional(self.ptr.relocation_by_addr(address))
    }

    /// Try to find the `.plt.got` relocation for the given symbol name
    pub fn relocation_for_symbol(&self, sym_name: &str) -> Option<Relocation<'_>> {
        into_optional(self.ptr.relocation_for_symbol(sym_name))
    }

    /// Try to find the symbol with the given name in the dynamic `.dynsym` table
    pub fn dynamic_symbol_by_name(&self, sym_name: &str) -> Option<Symbol<'_>> {
        into_optional(self.ptr.get_dynamic_symbol(sym_name))
    }

    /// Try to find the symbol with the given name in the debug `.symtab` table
    pub fn symtab_symbol_by_name(&self, sym_name: &str) -> Option<Symbol<'_>> {
        into_optional(self.ptr.get_symtab_symbol(sym_name))
    }

    /// Try to find the library (`DT_NEEDED`) with the given name
    pub fn get_library(&self, name: &str) -> Option<dynamic::Library<'_>> {
        into_optional(self.ptr.get_library(name))
    }

    /// Try to find the section that encompasses the given offset. `skip_nobits` can be used
    /// to include (or not) the `SHT_NOTBIT` sections
    pub fn section_from_offset(&self, offset: u64, skip_nobits: bool) -> Option<Section<'_>> {
        into_optional(self.ptr.section_from_offset(offset, skip_nobits))
    }

    /// Try to find the section that encompasses the given virtual address. `skip_nobits` can be used
    /// to include (or not) the `SHT_NOTBIT` sections
    pub fn section_from_virtual_address(&self, address: u64, skip_nobits: bool) -> Option<Section<'_>> {
        into_optional(self.ptr.section_from_virtual_address(address, skip_nobits))
    }

    /// Try to find the segment that encompasses the given virtual address
    pub fn segment_from_virtual_address(&self, address: u64) -> Option<Segment<'_>> {
        into_optional(self.ptr.segment_from_virtual_address(address))
    }

    /// Try to find the segment that encompasses the given offset
    pub fn segment_from_offset(&self, offset: u64) -> Option<Segment<'_>> {
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
                    T::from_u8(value).unwrap_or_else(|| panic!("Can't cast value: {value}"))
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u16>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u16,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u16(value).unwrap_or_else(|| panic!("Can't cast value: {value}"))
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u32>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u32,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u32(value).unwrap_or_else(|| panic!("Can't cast value: {value}"))
                },
                addr
            );
        }

        if size_of::<T>() == size_of::<u64>() {
            to_conv_result!(
                ffi::AbstractBinary::get_u64,
                self.ptr.as_ref().unwrap().as_ref(),
                |value| {
                    T::from_u64(value).unwrap_or_else(|| panic!("Can't cast value: {value}"))
                },
                addr
            );
        }

        Err(Error::NotSupported)
    }

    /// Write back the current ELF binary into the file specified in parameter
    pub fn write<P: AsRef<Path>>(&mut self, output: P) {
        self.ptr.as_mut().unwrap().write(output.as_ref().to_str().unwrap());
    }

    /// Write back the current ELF binary into the file specified in parameter with the
    /// configuration provided in the second parameter.
    pub fn write_with_config<P: AsRef<Path>>(&mut self, output: P, config: Config) {
        self.ptr
            .as_mut()
            .unwrap()
            .write_with_config(output.as_ref().to_str().unwrap(), config.to_ffi());
    }

    /// Add a library as dependency
    pub fn add_library<'a>(&'a mut self, library: &str) -> Library<'a> {
        Library::from_ffi(self.ptr.as_mut().unwrap().add_library(library))
    }

    /// Iterator over the functions found in this binary
    pub fn functions(&self) -> generic::Functions<'_> {
        generic::Functions::new(self.ptr.functions())
    }

    /// Try to find the dynamic entry associated with the given tag
    pub fn dynamic_entry_by_tag(&self, tag: dynamic::Tag) -> Option<dynamic::Entries<'_>> {
        into_optional(self.ptr.dynamic_entry_by_tag(tag.into()))
    }

    /// Look for the segment with the given type. If there are multiple segment
    /// with the same type, it returns the first one.
    pub fn segment_by_type(&self, seg_type: segment::Type) -> Option<Segment<'_>> {
        into_optional(self.ptr.segment_by_type(seg_type.into()))
    }

    /// Remove the given dynamic entry
    pub fn remove_dynamic_entry(&mut self, entry: impl dynamic::DynamicEntry) {
        self.ptr.pin_mut().remove_dynamic_entry(entry.as_base());
    }

    /// Remove the dynamic entries matching the given predicate.
    ///
    /// The function returns the number of entries that have been deleted.
    pub fn remove_dynamic_entry_if<P>(&mut self, predicate: P) -> usize
    where
        P: Fn(&dynamic::Entries) -> bool,
    {
        let entries = self.dynamic_entries()
            .filter(predicate)
            .map(|e| e.as_base().raw_ptr() )
            .collect::<Vec<_>>();

        let cnt = entries.len();

        for ffi_entry in entries {
            unsafe {
                self.ptr.pin_mut().remove_dynamic_entry_from_ptr(ffi_entry);
            }
        }
        cnt
    }

    /// Remove the `DT_NEEDED` dependency with the given name
    pub fn remove_library(&mut self, name: &str) {
        self.ptr.pin_mut().remove_library(name.to_string());
    }

    /// Add the provided segment to the binary. This function returns the
    /// newly added segment which could define additional attributes like the virtual address.
    pub fn add_segment(&mut self, segment: &Segment) -> Option<Segment<'_>> {
        into_optional(
            self.ptr
                .pin_mut()
                .add_segment(segment.ptr.as_ref().unwrap()),
        )
    }

    /// Change the path to the interpreter
    pub fn set_interpreter<P: AsRef<Path>>(&mut self, interpreter: P) {
        self.ptr.pin_mut().set_interpreter(interpreter.as_ref().to_str().unwrap());
    }

    /// Try to find the SymbolVersionRequirement associated with the given library
    /// name (e.g. `libc.so.6`)
    pub fn find_version_requirement(&self, libname: &str) -> Option<SymbolVersionRequirement<'_>> {
        into_optional(self.ptr.find_version_requirement(libname.to_string()))
    }

    /// Deletes all required symbol versions linked to the specified library name.
    /// The function returns true if the operation succeed, false otherwise.
    ///
    /// <div class='warning'>
    /// To maintain consistency, this function also removes versions
    /// associated with dynamic symbols that are linked to the specified
    /// library name.
    /// </div>
    pub fn remove_version_requirement(&mut self, libname: &str) -> bool {
        self.ptr
            .pin_mut()
            .remove_version_requirement(libname.to_string())
    }

    /// Remove the given segment. If `clear` is set, the original content of the
    /// segment will be filled with zeros before removal.
    pub fn remove_segment(&mut self, segment: Segment, clear: bool) {
        self.ptr
            .pin_mut()
            .remove_segment(segment.ptr.as_ref().unwrap(), clear)
    }

    /// Remove all segments associated with the given type.
    ///
    /// If `clear` is set, the original content of the segments will be filled
    /// with zeros before removal.
    pub fn remove_segments_by_type(&mut self, ty: segment::Type, clear: bool) {
        self.ptr.pin_mut().remove_segments_by_type(ty.into(), clear)
    }

    /// Return an iterator over all symbols (combined dynamic + symtab)
    pub fn symbols(&self) -> AllSymbols<'_> {
        AllSymbols::new(self.ptr.symbols())
    }

    /// Return all printable strings from the binary with a minimum length
    pub fn strings(&self, min_size: u64) -> Vec<String> {
        self.ptr.strings(min_size)
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Return the last offset used in binary according to sections table
    pub fn last_offset_section(&self) -> u64 {
        self.ptr.last_offset_section()
    }

    /// Return the last offset used in binary according to segments table
    pub fn last_offset_segment(&self) -> u64 {
        self.ptr.last_offset_segment()
    }

    /// Return the next virtual address available
    pub fn next_virtual_address(&self) -> u64 {
        self.ptr.next_virtual_address()
    }

    /// Return the offset of the end of the binary on disk
    pub fn eof_offset(&self) -> u64 {
        self.ptr.eof_offset()
    }

    /// Return the destructor functions (from `.fini_array`, `.dtors`, etc.)
    pub fn dtor_functions(&self) -> generic::Functions<'_> {
        generic::Functions::new(self.ptr.dtor_functions())
    }

    /// Return the overlay data
    pub fn overlay(&self) -> &[u8] {
        to_slice!(self.ptr.get_overlay());
    }

    /// Set the overlay data
    pub fn set_overlay(&mut self, data: &[u8]) {
        unsafe {
            self.ptr.pin_mut().set_overlay(data.as_ptr(), data.len() as u64);
        }
    }

    /// Check if the binary has a dynamic entry with the given tag
    pub fn has_dynamic_entry_tag(&self, tag: dynamic::Tag) -> bool {
        self.ptr.has_dynamic_entry_tag(tag.into())
    }

    /// Check if the binary has a segment with the given type
    pub fn has_segment_type(&self, ty: segment::Type) -> bool {
        self.ptr.has_segment_type(ty.into())
    }

    /// Check if the binary has a note with the given type
    pub fn has_note_type(&self, ty: super::note::Type) -> bool {
        self.ptr.has_note_type(ty.into())
    }

    /// Check if the binary has a section with the given type
    pub fn has_section_type(&self, ty: super::section::Type) -> bool {
        self.ptr.has_section_type(ty.into())
    }

    /// Try to find a note by its type
    pub fn note_by_type(&self, ty: super::note::Type) -> Option<super::note::Notes<'_>> {
        into_optional(self.ptr.get_note_by_type(ty.into()))
    }

    /// Try to find a section by its type
    pub fn section_by_type(&self, ty: super::section::Type) -> Option<Section<'_>> {
        into_optional(self.ptr.get_section_by_type(ty.into()))
    }

    /// Check if the binary has a section with the given name
    pub fn has_section(&self, name: &str) -> bool {
        self.ptr.has_section(name.to_string())
    }

    /// Check if the binary has a section that spans the given offset
    pub fn has_section_with_offset(&self, offset: u64) -> bool {
        self.ptr.has_section_with_offset(offset)
    }

    /// Check if the binary has a section that spans the given virtual address
    pub fn has_section_with_va(&self, va: u64) -> bool {
        self.ptr.has_section_with_va(va)
    }

    /// Check if the binary has a library dependency with the given name
    pub fn has_library(&self, name: &str) -> bool {
        self.ptr.has_library(name.to_string())
    }

    /// Check if the binary has a dynamic symbol with the given name
    pub fn has_dynamic_symbol(&self, name: &str) -> bool {
        self.ptr.has_dynamic_symbol(name.to_string())
    }

    /// Check if the binary has a symtab symbol with the given name
    pub fn has_symtab_symbol(&self, name: &str) -> bool {
        self.ptr.has_symtab_symbol(name.to_string())
    }

    /// Return the index of the given name in the dynamic symbol table
    pub fn dynsym_idx(&self, name: &str) -> Option<u64> {
        let idx = self.ptr.dynsym_idx(name.to_string());
        if idx < 0 {
            return None;
        }
        Some(idx as u64)
    }

    /// Return the index of the given name in the symtab symbol table, or -1
    pub fn symtab_idx(&self, name: &str) -> Option<u64> {
        let idx = self.ptr.symtab_idx(name.to_string());
        if idx < 0 {
            return None;
        }
        Some(idx as u64)
    }

    /// Patch the GOT/PLT entry for the given symbol name
    pub fn patch_pltgot(&mut self, symbol_name: &str, address: u64) {
        self.ptr.pin_mut().patch_pltgot_by_name(symbol_name.to_string(), address);
    }

    /// Add a section to the binary. If `loaded` is true, the section will be
    /// added in a way that it is loaded in memory. `pos` controls where the
    /// section is inserted.
    pub fn add_section(&mut self, section: &Section, loaded: bool, pos: SecInsertPos) -> Option<Section<'_>> {
        into_optional(
            self.ptr
                .pin_mut()
                .add_section(section.as_ffi(), loaded, pos.into()),
        )
    }

    /// Add a note to the binary
    pub fn add_note(&mut self, note: &super::note::Notes) -> super::note::Notes<'_> {
        super::note::Notes::from_ffi(
            self.ptr.pin_mut().add_note(note.as_ffi()),
        )
    }

    /// Add a dynamic relocation
    pub fn add_dynamic_relocation(&mut self, reloc: &Relocation) -> Relocation<'_> {
        Relocation::from_ffi(
            self.ptr.pin_mut().add_dynamic_relocation(reloc.as_ffi()),
        )
    }

    /// Add a `.plt.got` relocation
    pub fn add_pltgot_relocation(&mut self, reloc: &Relocation) -> Relocation<'_> {
        Relocation::from_ffi(
            self.ptr.pin_mut().add_pltgot_relocation(reloc.as_ffi()),
        )
    }

    /// Add a symbol to the `.symtab` table
    pub fn add_symtab_symbol(&mut self, symbol: &Symbol) -> Symbol<'_> {
        Symbol::from_ffi(
            self.ptr.pin_mut().add_symtab_symbol(symbol.as_ffi()),
        )
    }

    /// Add a symbol to the dynamic symbol table (`.dynsym`)
    pub fn add_dynamic_symbol(&mut self, symbol: &Symbol) -> Symbol<'_> {
        Symbol::from_ffi(
            self.ptr.pin_mut().add_dynamic_symbol(symbol.as_ffi()),
        )
    }

    /// Add an exported function with the given address and name
    pub fn add_exported_function(&mut self, address: u64, name: &str) -> Symbol<'_> {
        Symbol::from_ffi(
            self.ptr.pin_mut().add_exported_function(address, name.to_string()),
        )
    }

    /// Export the symbol with the given name, optionally setting its value (can be 0)
    pub fn export_symbol_by_name(&mut self, symbol_name: &str, value: u64) -> Symbol<'_> {
        Symbol::from_ffi(
            self.ptr.pin_mut().export_symbol_by_name(symbol_name.to_string(), value),
        )
    }

    /// Export an existing symbol
    pub fn export_symbol(&mut self, symbol: &Symbol) -> Symbol<'_> {
        Symbol::from_ffi(
            self.ptr.pin_mut().export_symbol_obj(symbol.as_ffi()),
        )
    }

    /// Remove the symtab symbol with the given name
    pub fn remove_symtab_symbol(&mut self, name: &str) {
        self.ptr.pin_mut().remove_symtab_symbol_by_name(name.to_string());
    }

    /// Remove the dynamic symbol with the given name
    pub fn remove_dynamic_symbol(&mut self, name: &str) {
        self.ptr.pin_mut().remove_dynamic_symbol_by_name(name.to_string());
    }

    /// Remove the given section. If `clear` is set, the section content will be
    /// filled with zeros before removal.
    pub fn remove_section(&mut self, section: &Section, clear: bool) {
        self.ptr.pin_mut().remove_section(section.as_ffi(), clear);
    }

    /// Remove the given note
    pub fn remove_note(&mut self, note: &super::note::Notes) {
        self.ptr.pin_mut().remove_note(note.as_ffi());
    }

    /// Extend the given segment by `size` bytes
    pub fn extend_segment(&mut self, segment: &Segment, size: u64) -> Option<Segment<'_>> {
        into_optional(
            self.ptr
                .pin_mut()
                .extend_segment(segment.ptr.as_ref().unwrap(), size),
        )
    }

    /// Extend the given section by `size` bytes
    pub fn extend_section(&mut self, section: &Section, size: u64) -> Option<Section<'_>> {
        into_optional(
            self.ptr
                .pin_mut()
                .extend_section(section.as_ffi(), size),
        )
    }

    /// Strip all debug symbols from the binary
    pub fn strip(&mut self) {
        self.ptr.pin_mut().strip();
    }

    /// Get the index of a section by its name. Returns `None` if not found.
    pub fn section_idx_by_name(&self, name: &str) -> Option<usize> {
        let idx = self.ptr.get_section_idx_by_name(name.to_string());
        if idx < 0 { None } else { Some(idx as usize) }
    }

    /// Get the index of the given section. Returns `None` if not found.
    pub fn section_idx(&self, section: &Section) -> Option<usize> {
        let idx = self.ptr.get_section_idx_by_section(section.as_ffi());
        if idx < 0 { None } else { Some(idx as usize) }
    }

    /// Relocate the PHDR table using the given strategy.
    /// Returns the new offset of the PHDR table.
    pub fn relocate_phdr_table(&mut self, reloc_type: PhdrReloc) -> u64 {
        self.ptr.pin_mut().relocate_phdr_table(reloc_type.into())
    }
}

impl AsFFI<ffi::ELF_Binary> for Binary {
    fn as_ffi(&self) -> &ffi::ELF_Binary {
        self.ptr.as_ref().unwrap()
    }

    fn as_mut_ffi(&mut self) -> std::pin::Pin<&mut ffi::ELF_Binary> {
        self.ptr.pin_mut()
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
declare_iterator!(
    AllSymbols,
    Symbol<'a>,
    ffi::ELF_Symbol,
    ffi::ELF_Binary,
    ffi::ELF_Binary_it_symbols
);
