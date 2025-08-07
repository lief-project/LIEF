//! Module for processing PDB file
//!
//! This module exposes an API similar to the [`crate::dwarf`] module to process PDB
//! files.
//!
//! One can instantiate a [`crate::pdb::DebugInfo`] using either [`crate::generic::Binary::debug_info`] or
//! [`crate::pdb::load`].
//!
//! ```
//! fn read_pdb(file: &str) {
//!     let pdb = lief::pdb::load(file).unwrap();
//!     for symbol in pdb.public_symbols() {
//!         println!("name: {}", symbol.name());
//!     }
//! }
//! ```

use std::path::Path;

use lief_ffi as ffi;

use crate::common::into_optional;

pub mod debug_info;
pub mod compilation_unit;
pub mod public_symbol;
pub mod function;
pub mod types;
pub mod build_metadata;

#[doc(inline)]
pub use debug_info::DebugInfo;

#[doc(inline)]
pub use compilation_unit::CompilationUnit;

#[doc(inline)]
pub use public_symbol::PublicSymbol;

#[doc(inline)]
pub use function::Function;

#[doc(inline)]
pub use types::Type;

#[doc(inline)]
pub use build_metadata::BuildMetadata;

/// Load a PDB from its filepath
pub fn load<P: AsRef<Path>>(path: P) -> Option<DebugInfo<'static>> {
    into_optional(ffi::PDB_DebugInfo::from_file(path.as_ref().to_str().unwrap()))
}

/// Check if the given file is a `PDB`
pub fn is_pdb<P: AsRef<Path>>(path: P) -> bool {
    ffi::PDB_Utils::is_pdb(path.as_ref().to_str().unwrap())
}
