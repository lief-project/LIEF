use std::marker::PhantomData;

use crate::{common::FromFFI, declare_iterator, generic};
use lief_ffi as ffi;

pub struct DelayImport<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DelayImport>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl DelayImport<'_> {
    pub fn attribute(&self) -> u32 {
        self.ptr.attribute()
    }
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }
    pub fn handle(&self) -> u32 {
        self.ptr.handle()
    }
    pub fn iat(&self) -> u32 {
        self.ptr.iat()
    }
    pub fn names_table(&self) -> u32 {
        self.ptr.names_table()
    }
    pub fn biat(&self) -> u32 {
        self.ptr.biat()
    }
    pub fn uiat(&self) -> u32 {
        self.ptr.uiat()
    }
    pub fn timestamp(&self) -> u32 {
        self.ptr.timestamp()
    }

    pub fn entries(&self) -> Entries {
        Entries::new(self.ptr.entries())
    }
}

impl std::fmt::Debug for DelayImport<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelayImport")
            .field("attribute", &self.attribute())
            .field("name", &self.name())
            .field("handle", &self.handle())
            .field("iat", &self.iat())
            .field("names_table", &self.names_table())
            .field("biat", &self.biat())
            .field("uiat", &self.uiat())
            .field("timestamp", &self.timestamp())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_DelayImport> for DelayImport<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DelayImport>) -> Self {
        DelayImport {
            ptr,
            _owner: PhantomData,
        }
    }
}

pub struct DelayImportEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_DelayImportEntry>,
    _owner: PhantomData<&'a ffi::PE_DelayImport>,
}

impl DelayImportEntry<'_> {
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
}

impl generic::Symbol for DelayImportEntry<'_> {
    fn as_generic(&self) -> &ffi::AbstractSymbol {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for DelayImportEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base = self as &dyn generic::Symbol;
        f.debug_struct("DelayImportEntry")
            .field("base", &base)
            .field("ordinal", &self.ordinal())
            .field("hint_name_rva", &self.hint_name_rva())
            .field("hint", &self.hint())
            .field("iat_value", &self.iat_value())
            .field("data", &self.data())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_DelayImportEntry> for DelayImportEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_DelayImportEntry>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    DelayImports,
    DelayImport<'a>,
    ffi::PE_DelayImport,
    ffi::PE_Binary,
    ffi::PE_Binary_it_delay_imports
);
declare_iterator!(
    Entries,
    DelayImportEntry<'a>,
    ffi::PE_DelayImportEntry,
    ffi::PE_DelayImport,
    ffi::PE_DelayImport_it_entries
);
