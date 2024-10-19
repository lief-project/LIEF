use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;

/// This structure represents a `dyld_cache_mapping_info` entry.
///
/// It provides information about the relationshiop between on-disk shared cache
/// and in-memory shared cache.
pub struct MappingInfo<'a> {
    ptr: cxx::UniquePtr<ffi::dsc_MappingInfo>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::dsc_MappingInfo> for MappingInfo<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::dsc_MappingInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl MappingInfo<'_> {
    /// The in-memory address where this dyld shared cache region is mapped
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

    /// Size of the region being mapped
    pub fn size(&self) -> u64 {
        self.ptr.size()
    }

    /// End virtual address of the region
    pub fn end_address(&self) -> u64 {
        self.ptr.end_address()
    }

    /// On-disk file offset
    pub fn file_offset(&self) -> u64 {
        self.ptr.file_offset()
    }

    /// Max memory protection
    pub fn max_prot(&self) -> u32 {
        self.ptr.max_prot()
    }

    /// Initial memory protection
    pub fn init_prot(&self) -> u32 {
        self.ptr.init_prot()
    }
}

impl std::fmt::Debug for MappingInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappingInfo")
            .field("address", &self.address())
            .field("end_address", &self.end_address())
            .field("size", &self.size())
            .field("file_offset", &self.file_offset())
            .field("max_prot", &self.max_prot())
            .field("init_prot", &self.init_prot())
            .finish()

    }
}
