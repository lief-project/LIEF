use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::declare_iterator;
use crate::generic;

use std::marker::PhantomData;

pub struct Export<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Export>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl Export<'_> {
    pub fn export_flags(&self) -> u32 {
        self.ptr.export_flags()
    }
    pub fn timestamp(&self) -> u32 {
        self.ptr.timestamp()
    }
    pub fn major_version(&self) -> u32 {
        self.ptr.major_version()
    }
    pub fn minor_version(&self) -> u32 {
        self.ptr.minor_version()
    }
    pub fn ordinal_base(&self) -> u32 {
        self.ptr.ordinal_base()
    }
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    pub fn entries(&self) -> ExportEntries {
        ExportEntries::new(self.ptr.entries())
    }
}

impl std::fmt::Debug for Export<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Export")
            .field("export_flags", &self.export_flags())
            .field("timestamp", &self.timestamp())
            .field("major_version", &self.major_version())
            .field("minor_version", &self.minor_version())
            .field("ordinal_base", &self.ordinal_base())
            .field("name", &self.name())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_Export> for Export<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Export>) -> Self {
        Export {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct Entry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ExportEntry>,
    _owner: PhantomData<&'a ffi::PE_Export>,
}

impl Entry<'_> {
    pub fn ordinal(&self) -> u16 {
        self.ptr.ordinal()
    }
    pub fn address(&self) -> u32 {
        self.ptr.address()
    }
    pub fn is_extern(&self) -> bool {
        self.ptr.is_extern()
    }
    pub fn is_forwarded(&self) -> bool {
        self.ptr.is_forwarded()
    }
}

impl generic::Symbol for Entry<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for Entry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("ExportEntry")
            .field("base", &base)
            .field("ordinal", &self.ordinal())
            .field("address", &self.address())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ExportEntry> for Entry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ExportEntry>) -> Self {
        Entry {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    ExportEntries,
    Entry<'a>,
    ffi::PE_ExportEntry,
    ffi::PE_Export,
    ffi::PE_Export_it_entries
);
