use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;

use crate::{declare_fwd_iterator, enum_from_int};

/// This class represents a Method (`LF_ONEMETHOD`) that can be defined in
/// ClassLike PDB type
pub struct Method<'a> {
    ptr: cxx::UniquePtr<ffi::PDB_types_Method>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::PDB_types_Method> for Method<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::PDB_types_Method>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    MethodAccess: u8 {
        /// No access specifier (or unknown)
        NONE = 0,
        /// Private access
        PRIVATE = 1,
        /// Protected access
        PROTECTED = 2,
        /// Public access
        PUBLIC = 3,
    }
}

enum_from_int! {
    #[allow(non_camel_case_types)]
    MethodType: u32 {
        /// Regular instance method
        VANILLA = 0x00,
        /// Virtual method
        VIRTUAL = 0x01,
        /// Static method
        STATIC = 0x02,
        /// Friend method
        FRIEND = 0x03,
        /// Virtual method that introduces a new vtable slot
        INTRODUCING_VIRTUAL = 0x04,
        /// Pure virtual method (abstract)
        PURE_VIRTUAL = 0x05,
        /// Pure virtual method that introduces a new vtable slot
        PURE_INTRODUCING_VIRTUAL = 0x06,
    }
}

impl Method<'_> {
    /// Name of the method
    pub fn name(&self) -> String {
        self.ptr.name().to_string()
    }

    pub fn get_type(&self) -> MethodType {
        MethodType::from(self.ptr.get_type())
    }

    pub fn access(&self) -> MethodAccess {
        MethodAccess::from(self.ptr.access())
    }
}

declare_fwd_iterator!(
    Methods,
    Method<'a>,
    ffi::PDB_types_Method,
    ffi::PDB_types_ClassLike,
    ffi::PDB_types_ClassLike_it_methods
);
