use lief_ffi as ffi;

pub mod debug_info;
pub mod compilation_unit;
pub mod function;
pub mod variable;
pub mod types;
pub mod scope;

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

/// Load a DWARF from its file path
pub fn load(path: &str) -> Option<DebugInfo> {
    into_optional(ffi::DWARF_DebugInfo::from_file(path))
}
