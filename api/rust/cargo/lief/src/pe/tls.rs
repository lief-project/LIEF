use lief_ffi as ffi;

use crate::common::FromFFI;
use crate::to_slice;
use std::marker::PhantomData;

pub struct TLS<'a> {
    ptr: cxx::UniquePtr<ffi::PE_TLS>,
    _owner: PhantomData<&'a ffi::PE_Binary>,
}

impl std::fmt::Debug for TLS<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TLS")
            .field("callbacks", &self.callbacks())
            .field("addressof_index", &self.addressof_index())
            .field("addressof_callbacks", &self.addressof_callbacks())
            .field("sizeof_zero_fill", &self.sizeof_zero_fill())
            .field("characteristics", &self.characteristics())
            .finish()
    }
}

impl TLS<'_> {
    pub fn callbacks(&self) -> Vec<u64> {
        Vec::from(self.ptr.callbacks().as_slice())
    }
    pub fn addressof_index(&self) -> u64 {
        self.ptr.addressof_index()
    }
    pub fn addressof_callbacks(&self) -> u64 {
        self.ptr.addressof_callbacks()
    }
    pub fn sizeof_zero_fill(&self) -> u64 {
        self.ptr.sizeof_zero_fill()
    }
    pub fn characteristics(&self) -> u64 {
        self.ptr.characteristics()
    }
    pub fn data_template(&self) -> &[u8] {
        to_slice!(self.ptr.data_template());
    }
    pub fn addressof_raw_data(&self) -> Vec<u64> {
        Vec::from(self.ptr.addressof_raw_data().as_slice())
    }
}

impl<'a> FromFFI<ffi::PE_TLS> for TLS<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_TLS>) -> Self {
        TLS {
            ptr,
            _owner: PhantomData,
        }
    }
}
