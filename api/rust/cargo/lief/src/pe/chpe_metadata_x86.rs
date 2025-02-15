use super::load_configuration::AsCHPEMetadata;
use crate::common::FromFFI;
use crate::to_opt;

use lief_ffi as ffi;
use std::marker::PhantomData;

/// This structure represents hybrid metadata for x86.
pub struct CHPEMetadata<'a> {
    ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataX86>,
    _owner: PhantomData<&'a ffi::PE_LoadConfiguration>,
}

impl<'a> FromFFI<ffi::PE_CHPEMetadataX86> for CHPEMetadata<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_CHPEMetadataX86>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl CHPEMetadata<'_> {
    pub fn chpe_code_address_range_offset(&self) -> u32 {
        self.ptr.chpe_code_address_range_offset()
    }

    pub fn chpe_code_address_range_count(&self) -> u32 {
        self.ptr.chpe_code_address_range_count()
    }

    pub fn wowa64_exception_handler_function_pointer(&self) -> u32 {
        self.ptr.wowa64_exception_handler_function_pointer()
    }

    pub fn wowa64_dispatch_call_function_pointer(&self) -> u32 {
        self.ptr.wowa64_dispatch_call_function_pointer()
    }

    pub fn wowa64_dispatch_indirect_call_function_pointer(&self) -> u32 {
        self.ptr.wowa64_dispatch_indirect_call_function_pointer()
    }

    pub fn wowa64_dispatch_indirect_call_cfg_function_pointer(&self) -> u32 {
        self.ptr.wowa64_dispatch_indirect_call_cfg_function_pointer()
    }

    pub fn wowa64_dispatch_ret_function_pointer(&self) -> u32 {
        self.ptr.wowa64_dispatch_ret_function_pointer()
    }

    pub fn wowa64_dispatch_ret_leaf_function_pointer(&self) -> u32 {
        self.ptr.wowa64_dispatch_ret_leaf_function_pointer()
    }

    pub fn wowa64_dispatch_jump_function_pointer(&self) -> u32 {
        self.ptr.wowa64_dispatch_jump_function_pointer()
    }

    pub fn compiler_iat_pointer(&self) -> Option<u32> {
        to_opt!(&lief_ffi::PE_CHPEMetadataX86::compiler_iat_pointer, &self);
    }

    pub fn wowa64_rdtsc_function_pointer(&self) -> Option<u32> {
        to_opt!(&lief_ffi::PE_CHPEMetadataX86::wowa64_rdtsc_function_pointer, &self);
    }
}

impl AsCHPEMetadata for CHPEMetadata<'_> {
    fn as_generic(&self) -> &ffi::PE_CHPEMetadata {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl std::fmt::Debug for CHPEMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CHPEMetadataX86")
            .field("chpe_code_address_range_offset", &self.chpe_code_address_range_offset())
            .field("chpe_code_address_range_count", &self.chpe_code_address_range_count())
            .field("wowa64_exception_handler_function_pointer", &self.wowa64_exception_handler_function_pointer())
            .field("wowa64_dispatch_call_function_pointer", &self.wowa64_dispatch_call_function_pointer())
            .field("wowa64_dispatch_indirect_call_function_pointer", &self.wowa64_dispatch_indirect_call_function_pointer())
            .field("wowa64_dispatch_indirect_call_cfg_function_pointer", &self.wowa64_dispatch_indirect_call_cfg_function_pointer())
            .field("wowa64_dispatch_ret_function_pointer", &self.wowa64_dispatch_ret_function_pointer())
            .field("wowa64_dispatch_ret_leaf_function_pointer", &self.wowa64_dispatch_ret_leaf_function_pointer())
            .field("wowa64_dispatch_jump_function_pointer", &self.wowa64_dispatch_jump_function_pointer())
            .field("compiler_iat_pointer", &self.compiler_iat_pointer())
            .field("wowa64_rdtsc_function_pointer", &self.wowa64_rdtsc_function_pointer())
            .finish()
    }
}

