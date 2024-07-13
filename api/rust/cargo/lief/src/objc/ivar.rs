use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::FromFFI;

/// This structure represents an instance variable (ivar)
pub struct IVar<'a> {
    ptr: cxx::UniquePtr<ffi::ObjC_IVar>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::ObjC_IVar> for IVar<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::ObjC_IVar>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl IVar<'_> {
    /// Name of the instance variable
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Type of the instance var in its mangled representation (`[29i]`)
    pub fn mangled_type(&self) -> String {
        self.ptr.mangled_type().to_string()
    }
}
