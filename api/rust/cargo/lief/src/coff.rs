//! Module for the COFF file format support in LIEF.
//!
//! The [`Binary`] structure exposes the main API to inspect a COFF file. It can be instantiated,
//! using either: [`crate::coff::parse`], [`crate::coff::Binary::parse`] or [`crate::Binary::parse`]
//!
//! ```
//! let coff = lief::coff::parse("demo.obj").unwrap();
//! for section in coff.sections() {
//!     println!("section: {}", section.name());
//! }
//! ```

pub mod string;
pub mod symbol;
pub mod binary;
pub mod header;
pub mod section;
pub mod relocation;

#[doc(inline)]
pub use symbol::Symbol;

#[doc(inline)]
pub use string::String;

#[doc(inline)]
pub use binary::Binary;

#[doc(inline)]
pub use section::Section;

#[doc(inline)]
pub use relocation::Relocation;

#[doc(inline)]
pub use header::{Header, RegularHeader, BigObjHeader};

/// Parse a COFF file from the given file path
pub fn parse(path: &str) -> Option<Binary> {
    Binary::parse(path)
}

pub fn is_coff(path: &str) -> bool {
    lief_ffi::COFF_Utils::is_coff(path)
}
