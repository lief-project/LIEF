use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::FromFFI;

/// This class represents a `@property` in Objective-C
pub struct Property<'a> {
    ptr: cxx::UniquePtr<ffi::ObjC_Property>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::ObjC_Property> for Property<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::ObjC_Property>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl Property<'_> {
    /// Name of the property
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// (raw) property's attributes (e.g. `T@"NSString",C,D,N`)
    pub fn attribute(&self) -> String {
        self.ptr.attribute().to_string()
    }
}

