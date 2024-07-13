use lief_ffi as ffi;

use std::marker::PhantomData;
use crate::common::{FromFFI, into_optional};
use crate::declare_fwd_iterator;

use super::{Class, Protocol};


/// This structure is the main interface to inspect Objective-C metadata
///
/// It can be access using the function [`crate::macho::Binary::objc_metadata`]
pub struct Metadata<'a> {
    ptr: cxx::UniquePtr<ffi::ObjC_Metadata>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::ObjC_Metadata> for Metadata<'_> {
    fn from_ffi(info: cxx::UniquePtr<ffi::ObjC_Metadata>) -> Self {
        Self {
            ptr: info,
            _owner: PhantomData
        }
    }
}

impl Metadata<'_> {
    /// Return an iterator over the different Objective-C classes (`@interface`)
    pub fn classes(&self) -> Classes {
        Classes::new(self.ptr.classes())
    }

    /// Return an iterator over the Objective-C protocols declared in this binary (`@protocol`).
    pub fn protocols(&self) -> Protocols {
        Protocols::new(self.ptr.protocols())
    }

    /// Try to find the Objective-C class with the given **mangled** name
    pub fn class_by_name(&self, name: &str) -> Option<Class> {
        into_optional(self.ptr.get_class(name))
    }

    /// Try to find the Objective-C protocol with the given **mangled** name
    pub fn protocol_by_name(&self, name: &str) -> Option<Protocol> {
        into_optional(self.ptr.get_protocol(name))
    }

    /// Generate a header-like of all the Objective-C metadata identified in the
    /// binary.
    pub fn to_decl(&self) -> String {
        self.ptr.to_decl().to_string()
    }
}

declare_fwd_iterator!(
    Classes,
    Class<'a>,
    ffi::ObjC_Class,
    ffi::ObjC_Metadata,
    ffi::ObjC_Metadata_it_classes
);

declare_fwd_iterator!(
    Protocols,
    Protocol<'a>,
    ffi::ObjC_Protocol,
    ffi::ObjC_Metadata,
    ffi::ObjC_Metadata_it_protocols
);
