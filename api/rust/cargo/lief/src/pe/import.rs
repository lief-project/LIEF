use std::marker::PhantomData;

use crate::common::into_optional;
use crate::declare_iterator;
use crate::pe::DataDirectory;
use crate::{common::FromFFI, generic};
use lief_ffi as ffi;

pub struct Import<'a> {
    ptr: cxx::UniquePtr<ffi::PE_Import>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for Import<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Import")
            .field("name", &self.name())
            .field("forwarder_chain", &self.forwarder_chain())
            .field("timedatestamp", &self.timedatestamp())
            .field("import_address_table_rva", &self.import_address_table_rva())
            .field("import_lookup_table_rva", &self.import_lookup_table_rva())
            .field("directory", &self.directory())
            .field("iat_directory", &self.iat_directory())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_Import> for Import<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_Import>) -> Self {
        Import {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Import<'_> {
    pub fn entries(&self) -> ImportEntries {
        ImportEntries::new(self.ptr.entries())
    }
    pub fn forwarder_chain(&self) -> u32 {
        self.ptr.forwarder_chain()
    }
    pub fn timedatestamp(&self) -> u32 {
        self.ptr.timedatestamp()
    }
    pub fn import_address_table_rva(&self) -> u32 {
        self.ptr.import_address_table_rva()
    }
    pub fn import_lookup_table_rva(&self) -> u32 {
        self.ptr.import_lookup_table_rva()
    }
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
    pub fn directory(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.directory())
    }
    pub fn iat_directory(&self) -> Option<DataDirectory> {
        into_optional(self.ptr.iat_directory())
    }
}

pub struct ImportEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ImportEntry>,
    _owner: PhantomData<&'a ffi::PE_Import>,
}

impl ImportEntry<'_> {
    pub fn is_ordinal(&self) -> bool {
        self.ptr.is_ordinal()
    }
    pub fn ordinal(&self) -> u16 {
        self.ptr.ordinal()
    }
    pub fn hint_name_rva(&self) -> u64 {
        self.ptr.hint_name_rva()
    }
    pub fn hint(&self) -> u16 {
        self.ptr.hint()
    }
    pub fn iat_value(&self) -> u64 {
        self.ptr.iat_value()
    }
    pub fn data(&self) -> u64 {
        self.ptr.data()
    }
    pub fn iat_address(&self) -> u64 {
        self.ptr.iat_address()
    }
}

impl<'a> FromFFI<ffi::PE_ImportEntry> for ImportEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ImportEntry>) -> Self {
        ImportEntry {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl generic::Symbol for ImportEntry<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for ImportEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("ImportEntry")
            .field("base", &base)
            .field("ordinal", &self.ordinal())
            .field("hint_name_rva", &self.hint_name_rva())
            .field("hint", &self.hint())
            .field("iat_value", &self.iat_value())
            .field("data", &self.data())
            .field("iat_address", &self.iat_address())
            .finish()
    }
}

declare_iterator!(
    ImportEntries,
    ImportEntry<'a>,
    ffi::PE_ImportEntry,
    ffi::PE_Import,
    ffi::PE_Import_it_entries
);
declare_iterator!(
    Imports,
    Import<'a>,
    ffi::PE_Import,
    ffi::PE_Binary,
    ffi::PE_Binary_it_imports
);
