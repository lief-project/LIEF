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
