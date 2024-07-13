use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::{FromFFI, into_optional};
use crate::generic;

use super::compilation_unit::CompilationUnits;
use super::public_symbol::PublicSymbols;
use super::types::{Types, Type};
use super::PublicSymbol;

/// Main interface over a PDB.
///
/// One can instantiate this structure with [`crate::pdb::load`],
/// [`DebugInfo::from`] or using [`crate::generic::Binary::debug_info`].
pub struct DebugInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_DebugInfo>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_DebugInfo> for DebugInfo<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::PDB_DebugInfo>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl DebugInfo<'_> {
    /// Create a DebugInfo from a PDB file path
    pub fn from(path: &str) -> Option<DebugInfo> {
        into_optional(ffi::PDB_DebugInfo::from_file(path))
    }

    /// The number of times the PDB file has been written.
    pub fn age(&self) -> u32 {
        self.ptr.age()
    }

    /// Unique identifier of the PDB file
    pub fn guid(&self) -> String {
        self.ptr.guid().to_string()
    }

    /// Iterator over the CompilationUnit from the PDB's DBI stream.
    /// [`crate::pdb::CompilationUnit`] are also named "Module" in the PDB's official documentation
    pub fn compilation_units(&self) -> CompilationUnits {
        CompilationUnits::new(self.ptr.compilation_units())
    }

    /// Return an iterator over the public symbol stream ([`PublicSymbol`])
    pub fn public_symbols(&self) -> PublicSymbols {
        PublicSymbols::new(self.ptr.public_symbols())
    }

    /// Try to find the [`PublicSymbol`] from the given name (based on the public symbol stream)
    ///
    ///
    /// ```
    /// if let Some(symbol) = info.public_symbol_by_name("MiSyncSystemPdes") {
    ///   // FOUND!
    /// }
    /// ```
    pub fn public_symbol_by_name(&self, name: &str) -> Option<PublicSymbol> {
        into_optional(self.ptr.public_symbol_by_name(name))
    }

    /// Return an iterator over the different [`crate::pdb::Type`] registered for this PDB file
    pub fn types(&self) -> Types {
        Types::new(self.ptr.types())
    }

    /// Try to find the type with the given name
    pub fn type_by_name(&self, name: &str) -> Option<Type> {
        into_optional(self.ptr.find_type(name))
    }
}

impl generic::DebugInfo for DebugInfo<'_> {
    fn as_generic(&self) -> &ffi::AbstracDebugInfo {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
