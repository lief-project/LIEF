use lief_ffi as ffi;
use num_bigint::BigUint;

use crate::common::FromFFI;
use std::marker::PhantomData;

pub struct RsaInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_RsaInfo>,
    _owner: PhantomData<&'a ()>,
}

impl std::fmt::Debug for RsaInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RsaInfo")
            .field("key_size", &self.key_size())
            .field("has_public_key", &self.has_public_key())
            .field("has_private_key", &self.has_private_key())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_RsaInfo> for RsaInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_RsaInfo>) -> Self {
        RsaInfo {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl<'a> RsaInfo<'a> {
    #[allow(non_snake_case)]
    pub fn N(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.N().as_slice())
    }
    #[allow(non_snake_case)]
    pub fn E(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.E().as_slice())
    }
    #[allow(non_snake_case)]
    pub fn D(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.D().as_slice())
    }
    #[allow(non_snake_case)]
    pub fn P(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.P().as_slice())
    }
    #[allow(non_snake_case)]
    pub fn Q(&self) -> BigUint {
        BigUint::from_bytes_le(self.ptr.Q().as_slice())
    }
    pub fn key_size(&self) -> u32 {
        self.ptr.key_size()
    }
    pub fn has_public_key(&self) -> bool {
        self.ptr.has_public_key()
    }
    pub fn has_private_key(&self) -> bool {
        self.ptr.has_private_key()
    }
}
