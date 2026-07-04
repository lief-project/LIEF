use lief_ffi as ffi;

use crate::common::FromFFI;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// This structure represents a location in the different debug formats (DWARF/PDB)
pub struct DebugLocation {
    /// Line number
    pub line: u64,

    /// Filename or filepath
    pub file: String,
}

impl FromFFI<ffi::DebugLocation> for DebugLocation {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DebugLocation>) -> Self {
        DebugLocation {
            line: ptr.line(),
            file: ptr.file().to_string(),
        }
    }
}
