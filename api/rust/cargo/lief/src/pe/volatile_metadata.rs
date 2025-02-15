//! PE volatile memory metadata
use std::marker::PhantomData;

use crate::{common::FromFFI, declare_iterator};
use lief_ffi as ffi;

/// This class represents volatile metadata which can be enabled at link time
/// with `/volatileMetadata`.
///
/// This metadata aims to improve performances when running x64 code on ARM64.
pub struct VolatileMetadata<'a> {
    ptr: cxx::UniquePtr<ffi::PE_VolatileMetadata>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_VolatileMetadata> for VolatileMetadata<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_VolatileMetadata>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl VolatileMetadata<'_> {
    pub fn size(&self) -> u32 {
        self.ptr.size()
    }

    pub fn min_version(&self) -> u16 {
        self.ptr.min_version()
    }

    pub fn max_version(&self) -> u16 {
        self.ptr.max_version()
    }

    pub fn access_table_rva(&self) -> u32 {
        self.ptr.access_table_rva()
    }

    pub fn access_table_size(&self) -> u32 {
        self.ptr.access_table_size()
    }

    pub fn info_range_rva(&self) -> u32 {
        self.ptr.info_range_rva()
    }

    pub fn info_ranges_size(&self) -> u32 {
        self.ptr.info_ranges_size()
    }

    pub fn info_ranges(&self) -> Ranges {
        Ranges::new(self.ptr.info_ranges())
    }

    pub fn access_table(&self) -> Vec<u32> {
        Vec::from(self.ptr.access_table().as_slice())
    }
}

impl std::fmt::Debug for VolatileMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolatileMetadata")
            .field("size", &self.size())
            .field("min_version", &self.min_version())
            .field("max_version", &self.max_version())
            .field("access_table_rva", &self.access_table_rva())
            .field("access_table_size", &self.access_table_size())
            .field("info_range_rva", &self.info_range_rva())
            .field("info_ranges_size", &self.info_ranges_size())
            .finish()
    }
}

impl std::fmt::Display for VolatileMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.ptr.to_string())
    }
}

pub struct Range<'a> {
    ptr: cxx::UniquePtr<ffi::PE_VolatileMetadata_range_t>,
    _owner: PhantomData<&'a ffi::PE_VolatileMetadata>,
}

impl<'a> FromFFI<ffi::PE_VolatileMetadata_range_t> for Range<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_VolatileMetadata_range_t>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl Range<'_> {
    pub fn start(&self) -> u32 {
        self.ptr.start()
    }

    pub fn end(&self) -> u32 {
        self.ptr.end()
    }

    pub fn size(&self) -> u32 {
        self.ptr.size()
    }
}

impl std::fmt::Debug for Range<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Range")
            .field("start", &self.start())
            .field("end", &self.end())
            .field("size", &self.size())
            .finish()
    }
}

declare_iterator!(
    Ranges,
    Range<'a>,
    ffi::PE_Range,
    ffi::PE_VolatileMetadata,
    ffi::PE_VolatileMetadata_it_ranges
);


