use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use std::marker::PhantomData;
use crate::dsc::UUID;
use super::DyldSharedCache;

/// This class represents a subcache in the case of large/split dyld shared
/// cache.
///
/// It mirror (and abstracts) the original `dyld_subcache_entry` / `dyld_subcache_entry_v1`
pub struct SubCache<'a> {
    ptr: cxx::UniquePtr<ffi::dsc_SubCache>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::dsc_SubCache> for SubCache<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::dsc_SubCache>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl SubCache<'_> {
    /// The uuid of the subcache file
    pub fn uuid(&self) -> UUID {
        let vec = Vec::from(self.ptr.uuid().as_slice());
        assert!(vec.len() == 16);
        let mut uuid: UUID = [0; 16];
        for i in 0..16 {
            uuid[i] = vec[i] as u8;
        }
        uuid
    }

    /// The offset of this subcache from the main cache base address
    pub fn vm_offset(&self) -> u64 {
        self.ptr.vm_offset()
    }

    /// The file name suffix of the subCache file (e.g. `.25.data`, `.03.development`)
    pub fn suffix(&self) -> String {
        self.ptr.suffix().to_string()
    }

    /// The associated DyldSharedCache object for this subcache
    pub fn cache(&self) -> Option<DyldSharedCache> {
        into_optional(self.ptr.cache())
    }
}

impl std::fmt::Debug for SubCache<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubCache")
            .field("uuid", &self.uuid())
            .field("vm_offset", &self.vm_offset())
            .field("suffix", &self.suffix())
            .finish()

    }
}
