//! Module for processing DWARF debug info
//!
//! This module exposes an API similar to the [`crate::pdb`] module to process DWARF
//! debug info (embedded or not).
//!
//! One can instantiate a [`crate::dwarf::DebugInfo`] using either [`crate::generic::Binary::debug_info`] or
//! [`crate::dwarf::load`] for external DWARF files.
//!
//! ```
//! fn from_binary(elf: &lief::elf::Binary) {
//!     if let Some(lief::DebugInfo::Dwarf(dwarf)) = elf.debug_info() {
//!         for complilation_unit in dwarf.compilation_units() {
//!             println!("{}", complilation_unit.name());
//!         }
//!     }
//! }
//!
//! fn from_external(dwarf_file: &str) {
//!     let debug_info = lief::dwarf::load(dwarf_file).unwrap();
//!     for complilation_unit in debug_info.compilation_units() {
//!         println!("{}", complilation_unit.name());
//!     }
//! }
//! ```

use lief_ffi as ffi;

pub mod debug_info;
pub mod compilation_unit;
pub mod function;
pub mod variable;
pub mod types;
pub mod scope;
pub mod parameters;

use crate::common::into_optional;

#[doc(inline)]
pub use debug_info::DebugInfo;

#[doc(inline)]
pub use compilation_unit::CompilationUnit;

#[doc(inline)]
pub use function::Function;

#[doc(inline)]
pub use variable::Variable;

#[doc(inline)]
pub use scope::Scope;

#[doc(inline)]
pub use types::Type;

#[doc(inline)]
pub use parameters::{Parameter, Parameters};

/// Load a DWARF from its file path
pub fn load(path: &str) -> Option<DebugInfo> {
    into_optional(ffi::DWARF_DebugInfo::from_file(path))
}
