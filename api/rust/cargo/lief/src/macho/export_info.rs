use lief_ffi as ffi;

use bitflags::bitflags;
use std::{fmt, marker::PhantomData};

use crate::common::{into_optional, FromFFI};

use super::{commands::Dylib, Symbol};

/// This structure represents an export (info) in a Mach-O binary
pub struct ExportInfo<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_ExportInfo>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Kind {
    REGULAR,
    THREAD_LOCAL,
    ABSOLUTE,
    UNKNOWN(u64),
}

impl From<u64> for Kind {
    fn from(value: u64) -> Self {
        match value {
            0x00000000 => Kind::REGULAR,
            0x00000001 => Kind::THREAD_LOCAL,
            0x00000002 => Kind::ABSOLUTE,
            _ => Kind::UNKNOWN(value),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u64 {
        const WEAK_DEFINITION = 0x4;
        const REEXPORT = 0x8;
        const STUB_AND_RESOLVER = 0x10;
    }
}


impl From<u64> for Flags {
    fn from(value: u64) -> Self {
        Flags::from_bits_truncate(value)
    }
}
impl From<Flags> for u64 {
    fn from(value: Flags) -> Self {
        value.bits()
    }
}
impl std::fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl fmt::Debug for ExportInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportInfo")
            .field("node_offset", &self.node_offset())
            .field("flags", &self.flags())
            .field("address", &self.address())
            .field("other", &self.other())
            .field("kind", &self.kind())
            .finish()
    }
}

impl ExportInfo<'_> {
    /// Original offset in the export Trie
    pub fn node_offset(&self) -> u64 {
        self.ptr.node_offset()
    }

    pub fn flags(&self) -> Flags {
        Flags::from(self.ptr.flags())
    }

    /// The address of the export
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    pub fn other(&self) -> u64 {
        self.ptr.other()
    }

    /// The export's kind (regular, thread local, absolute, ...)
    pub fn kind(&self) -> Kind {
        Kind::from(self.ptr.kind())
    }

    /// Symbol associated with this export
    pub fn symbol(&self) -> Option<Symbol> {
        into_optional(self.ptr.symbol())
    }

    /// If the export is a re-export ([`Flags::REEXPORT`]) this function returns
    /// the symbol being re-exported
    pub fn alias(&self) -> Option<Symbol> {
        into_optional(self.ptr.alias())
    }

    /// If the export is a re-export ([`Flags::REEXPORT`]) this function returns
    /// the library from which the symbol is re-exported
    pub fn alias_library(&self) -> Option<Dylib> {
        into_optional(self.ptr.alias_library())
    }
}

impl<'a> FromFFI<ffi::MachO_ExportInfo> for ExportInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_ExportInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}
