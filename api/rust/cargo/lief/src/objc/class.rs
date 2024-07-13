use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::{FromFFI, into_optional};
use crate::declare_fwd_iterator;
use super::{Method, Protocol, IVar, Property};

/// This class represents an Objective-C class (`@interface`)
pub struct Class<'a> {
    ptr: cxx::UniquePtr<ffi::ObjC_Class>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::ObjC_Class> for Class<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::ObjC_Class>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl Class<'_> {
    /// Name of the class
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    /// Demangled name of the class
    pub fn demangled_name(&self) -> String {
        self.ptr.demangled_name().to_string()
    }

    /// Parent class in case of inheritance
    pub fn super_class(&self) -> Option<Class> {
        into_optional(self.ptr.super_class())
    }

    pub fn is_meta(&self) -> bool {
        self.ptr.is_meta()
    }

    /// Iterator over the different [`Method`] defined by this class
    pub fn methods(&self) -> Methods {
        Methods::new(self.ptr.methods())
    }

    /// Iterator over the different [`Protocol`] implemented by this class
    pub fn protocols(&self) -> Protocols {
        Protocols::new(self.ptr.protocols())
    }

    /// Iterator over the [`Property`] of this class
    pub fn properties(&self) -> Properties {
        Properties::new(self.ptr.properties())
    }

    /// Iterator over the different instance variables ([`IVar`]) defined in this class
    pub fn ivars(&self) -> IVars {
        IVars::new(self.ptr.ivars())
    }
}

declare_fwd_iterator!(
    Methods,
    Method<'a>,
    ffi::ObjC_Method,
    ffi::ObjC_Class,
    ffi::ObjC_Class_it_methods
);

declare_fwd_iterator!(
    Protocols,
    Protocol<'a>,
    ffi::ObjC_Protocol,
    ffi::ObjC_Class,
    ffi::ObjC_Class_it_protocols
);

declare_fwd_iterator!(
    Properties,
    Property<'a>,
    ffi::ObjC_Property,
    ffi::ObjC_Class,
    ffi::ObjC_Class_it_properties
);

declare_fwd_iterator!(
    IVars,
    IVar<'a>,
    ffi::ObjC_IVar,
    ffi::ObjC_Class,
    ffi::ObjC_Class_it_ivars
);
