//! Module for the ELF file format support in LIEF.
//!
//! The [`Binary`] structure exposes the main API to inspect an ELF file. It can be instantiated,
//! using either: [`crate::elf::parse`], [`crate::elf::Binary::parse`] or [`crate::Binary::parse`]
//!
//! ```
//! let elf = lief::elf::parse("/bin/ls").unwrap();
//! for section in elf.sections() {
//!     println!("section: {}", section.name());
//! }
//! ```

use crate::common::AsFFI;
use lief_ffi as ffi;
use std::path::Path;

pub mod binary;
pub mod builder;
pub mod dynamic;
pub mod hash;
pub mod header;
pub mod note;
pub mod parser_config;
pub mod relocation;
pub mod section;
pub mod segment;
pub mod symbol;
pub mod symbol_versioning;

#[doc(inline)]
pub use binary::Binary;

#[doc(inline)]
pub use header::Header;

#[doc(inline)]
pub use section::Section;

#[doc(inline)]
pub use segment::Segment;

#[doc(inline)]
pub use symbol::Symbol;

#[doc(inline)]
pub use hash::Sysv as SysvHash;

#[doc(inline)]
pub use hash::Gnu as GnuHash;

#[doc(inline)]
pub use note::Notes;

#[doc(inline)]
pub use dynamic::Entries as DynamicEntries;

#[doc(inline)]
pub use relocation::Relocation;

#[doc(inline)]
pub use symbol_versioning::{
    SymbolVersion, SymbolVersionAux, SymbolVersionAuxRequirement, SymbolVersionDefinition,
    SymbolVersionRequirement,
};

#[doc(inline)]
pub use parser_config::Config as ParserConfig;

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

/// Parse an ELF file from the given filepath
pub fn parse<P: AsRef<Path>>(path: P) -> Option<Binary> {
    Binary::parse(path)
}

/// Parse an ELF file from the given filepath and configuration
pub fn parse_with_config<P: AsRef<Path>>(path: P, config: &ParserConfig) -> Option<Binary> {
    Binary::parse_with_config(path, config)
}

/// Check that the layout of the given binary is correct
pub fn check_layout(binary: &Binary) -> Result<(), String> {
    cxx::let_cxx_string!(error = "");
    unsafe {
        if ffi::ELF_Utils::check_layout(binary.as_ffi(), error.as_mut().get_unchecked_mut()) {
            return Ok(());
        }
    }
    Err(error.to_string())
}
