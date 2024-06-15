use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;

pub struct CodeIntegrity<'a> {
    ptr: cxx::UniquePtr<ffi::PE_CodeIntegrity>,
    _owner: PhantomData<&'a ffi::PE_LoadConfigurationV2>,
}

impl std::fmt::Debug for CodeIntegrity<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeIntegrity")
            .field("flags", &self.flags())
            .field("catalog", &self.catalog())
            .field("catalog_offset", &self.catalog_offset())
            .field("reserved", &self.reserved())
            .finish()
    }
}

impl CodeIntegrity<'_> {
    /// Flags to indicate if CI information is available, etc.
    pub fn flags(&self) -> u16 {
        self.ptr.flags()
    }

    /// 0xFFFF means not available
    pub fn catalog(&self) -> u16 {
        self.ptr.catalog()
    }
    pub fn catalog_offset(&self) -> u32 {
        self.ptr.catalog_offset()
    }

    /// Additional bitmask to be defined later
    pub fn reserved(&self) -> u32 {
        self.ptr.reserved()
    }
}

impl<'a> FromFFI<ffi::PE_CodeIntegrity> for CodeIntegrity<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_CodeIntegrity>) -> Self {
        CodeIntegrity {
            ptr,
            _owner: PhantomData,
        }
    }
}
