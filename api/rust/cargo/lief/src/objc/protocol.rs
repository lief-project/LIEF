use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::FromFFI;
use crate::declare_fwd_iterator;

use super::{Property, Method};

/// This class represents an Objective-C `@protocol`
pub struct Protocol<'a> {
    ptr: cxx::UniquePtr<ffi::ObjC_Protocol>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::ObjC_Protocol> for Protocol<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::ObjC_Protocol>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl Protocol<'_> {
    /// Mangled name of the protocol
    pub fn mangled_name(&self) -> String {
        self.ptr.mangled_name().to_string()
    }

    /// Iterator over the methods that could be overridden
    pub fn optional_methods(&self) -> OptionalMethods {
        OptionalMethods::new(self.ptr.optional_methods())
    }

    /// Iterator over the methods of this protocol that must be implemented
    pub fn required_methods(&self) -> RequiredMethods {
        RequiredMethods::new(self.ptr.required_methods())
    }

    /// Iterator over the properties defined in this protocol
    pub fn properties(&self) -> Properties {
        Properties::new(self.ptr.properties())
    }
}

declare_fwd_iterator!(
    OptionalMethods,
    Method<'a>,
    ffi::ObjC_Method,
    ffi::ObjC_Protocol,
    ffi::ObjC_Protocol_it_opt_methods
);

declare_fwd_iterator!(
    RequiredMethods,
    Method<'a>,
    ffi::ObjC_Method,
    ffi::ObjC_Protocol,
    ffi::ObjC_Protocol_it_req_methods
);

declare_fwd_iterator!(
    Properties,
    Property<'a>,
    ffi::ObjC_Property,
    ffi::ObjC_Protocol,
    ffi::ObjC_Protocol_it_properties
);
