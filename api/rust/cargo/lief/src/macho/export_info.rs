use lief_ffi as ffi;
use std::{fmt, marker::PhantomData};

use crate::common::{into_optional, FromFFI};

use super::{commands::Dylib, Symbol};

pub struct ExportInfo<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_ExportInfo>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum KIND {
    REGULAR,
    THREAD_LOCAL,
    ABSOLUTE,
    UNKNOWN(u64),
}

impl KIND {
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00000000 => KIND::REGULAR,
            0x00000001 => KIND::THREAD_LOCAL,
            0x00000002 => KIND::ABSOLUTE,
            _ => KIND::UNKNOWN(value),
        }
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
    pub fn node_offset(&self) -> u64 {
        self.ptr.node_offset()
    }

    pub fn flags(&self) -> u64 {
        self.ptr.flags()
    }

    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    pub fn other(&self) -> u64 {
        self.ptr.other()
    }

    pub fn kind(&self) -> KIND {
        KIND::from_value(self.ptr.other())
    }

    pub fn symbol(&self) -> Option<Symbol> {
        into_optional(self.ptr.symbol())
    }

    pub fn alias(&self) -> Option<Symbol> {
        into_optional(self.ptr.alias())
    }

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
