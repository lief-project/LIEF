use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::FromFFI;

/// This structure represents an Objective-C Method
pub struct Method<'a> {
    ptr: cxx::UniquePtr<ffi::ObjC_Method>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::ObjC_Method> for Method<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::ObjC_Method>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl Method<'_> {
    /// Name of the method
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Prototype of the method in its mangled representation (e.g. `@16@0:8`)
    pub fn mangled_type(&self) -> String {
        self.ptr.mangled_type().to_string()
    }

    /// Virtual address where this method is implemented in the binary
    pub fn address(&self) -> u64 {
        self.ptr.address()
    }

  /// Whether it's an instance method
    pub fn is_instance(&self) -> bool {
        self.ptr.is_instance()
    }
}

