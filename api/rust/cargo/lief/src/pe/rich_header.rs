use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::{common::FromFFI, declare_iterator};

pub struct RichHeader<'a> {
    ptr: cxx::UniquePtr<ffi::PE_RichHeader>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for RichHeader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RichHeader")
            .field("key", &self.key())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_RichHeader> for RichHeader<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_RichHeader>) -> Self {
        RichHeader {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> RichHeader<'a> {
    pub fn key(&self) -> u32 {
        self.ptr.key()
    }

    pub fn entries(&self) -> Entries {
        Entries::new(self.ptr.entries())
    }
}

pub struct RichEntry<'a> {
    ptr: cxx::UniquePtr<ffi::PE_RichEntry>,
    _owner: PhantomData<&'a ffi::PE_RichHeader>,
}

impl RichEntry<'_> {
    pub fn id(&self) -> u16 {
        self.ptr.id()
    }
    pub fn build_id(&self) -> u16 {
        self.ptr.build_id()
    }
    pub fn count(&self) -> u32 {
        self.ptr.count()
    }
}

impl std::fmt::Debug for RichEntry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RichEntry")
            .field("id", &self.id())
            .field("build_id", &self.build_id())
            .field("count", &self.count())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_RichEntry> for RichEntry<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_RichEntry>) -> Self {
        RichEntry {
            ptr,
            _owner: PhantomData,
        }
    }
}

declare_iterator!(
    Entries,
    RichEntry<'a>,
    ffi::PE_RichEntry,
    ffi::PE_RichHeader,
    ffi::PE_RichHeader_it_entries
);
