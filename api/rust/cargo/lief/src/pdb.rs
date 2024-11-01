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

use lief_ffi as ffi;

use crate::common::into_optional;

pub mod debug_info;
pub mod compilation_unit;
pub mod public_symbol;
pub mod function;
pub mod types;

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

/// Load a PDB from its file path
pub fn load(path: &str) -> Option<DebugInfo> {
    into_optional(ffi::PDB_DebugInfo::from_file(path))
}
