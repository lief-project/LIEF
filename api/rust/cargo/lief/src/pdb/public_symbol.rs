//! This module wraps a PDB public symbol (stream number `n+5`)

use lief_ffi as ffi;

use std::marker::PhantomData;

use crate::common::FromFFI;
use crate::declare_fwd_iterator;

/// This class provides general information (RVA, name) about a symbol
/// from the PDB's public symbol stream (or Public symbol hash stream)
pub struct PublicSymbol<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_PublicSymbol>,
    _owner: PhantomData<&'a ()>,
}


impl FromFFI<ffi::PDB_PublicSymbol> for PublicSymbol<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PDB_PublicSymbol>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl PublicSymbol<'_> {
    /// Name of the symbol
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Demangled representation of the symbol
    pub fn demangled_name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Name of the section in which this symbol is defined (e.g. `.text`).
    pub fn section_name(&self) -> Option<String> {
        let name = self.ptr.section_name().to_string();
        if !name.is_empty() {
            Some(name)
        } else {
            None
        }
    }

    /// **Relative** Virtual Address of this symbol.
    ///
    /// This function returns 0 if the RVA can't be computed.
    pub fn rva(&self) -> u32 {
        self.ptr.RVA()
    }
}

declare_fwd_iterator!(
    PublicSymbols,
    PublicSymbol<'a>,
    ffi::PDB_PublicSymbol,
    ffi::PDB_DebugInfo,
    ffi::PDB_DebugInfo_it_public_symbols
);
