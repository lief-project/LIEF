//! Module for the Mach-O file format support in LIEF.
//!
//! To get started, one can use [`crate::macho::parse`], [`crate::macho::FatBinary::parse`] or
//! [`crate::Binary::parse`] to instantiate a [`crate::macho::FatBinary`].
//!
//! Even though the targeted Mach-O binary is not FAT, LIEF **always** return a [`crate::macho::FatBinary`]
//! which can wrap a single [`Binary`].
//!
//! ```
//! let fat = lief::macho::parse("non-fat.macho").unwrap();
//! assert!(fat.iter().len() == 1);
//!
//! let fat = lief::macho::parse("real-fat.macho").unwrap();
//! assert!(fat.iter().len() > 1);
//! ```
//!
//! The [`Binary`] structure exposes the main interface to inspect or modify Mach-O binaries:
//!
//! ```
//! fn inspect_macho(macho: &lief::macho::Binary) {
//!     for cmd in macho.commands() {
//!         println!("{:?}", cmd);
//!     }
//! }
//! ```
//!
pub mod binary;
pub mod binding_info;
pub mod commands;
pub mod export_info;
pub mod fat_binary;
pub mod relocation;
pub mod section;
pub mod symbol;
pub mod header;
pub mod stub;
pub mod builder;

#[doc(inline)]
pub use binary::Binary;
#[doc(inline)]
pub use binding_info::BindingInfo;
#[doc(inline)]
pub use export_info::ExportInfo;
#[doc(inline)]
pub use fat_binary::FatBinary;
#[doc(inline)]
pub use relocation::Relocation;
#[doc(inline)]
pub use section::Section;
#[doc(inline)]
pub use symbol::Symbol;
#[doc(inline)]
pub use commands::Commands;
#[doc(inline)]
pub use header::Header;
#[doc(inline)]
pub use stub::Stub;

/// Parse a Mach-O file from the given file path
pub fn parse(path: &str) -> Option<FatBinary> {
    FatBinary::parse(path)
}
