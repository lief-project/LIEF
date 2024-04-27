use std::marker::PhantomData;

use lief_ffi as ffi;

use crate::common::FromFFI;

pub struct ContentInfo<'a> {
    ptr: cxx::UniquePtr<ffi::PE_ContentInfo>,
    _owner: PhantomData<&'a ffi::PE_Signature>,
}

impl ContentInfo<'_> {
    pub fn content_type(&self) -> String {
        self.ptr.content_type().to_string()
    }
}

impl std::fmt::Debug for ContentInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentInfo")
            .field("content_type", &self.content_type())
            .finish()
    }
}

impl<'a> FromFFI<ffi::PE_ContentInfo> for ContentInfo<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::PE_ContentInfo>) -> Self {
        ContentInfo {
            ptr,
            _owner: PhantomData,
        }
    }
}
