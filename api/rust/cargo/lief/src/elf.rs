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

pub mod binary;
pub mod builder;
pub mod dynamic;
pub mod hash;
pub mod header;
pub mod note;
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

/// Parse an ELF file from the given file path
pub fn parse(path: &str) -> Option<Binary> {
    Binary::parse(path)
}
