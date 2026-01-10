use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;

use crate::declare_fwd_iterator;

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

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MethodAccess {
    /// No access specifier (or unknown)
    NONE,
    /// Private access
    PRIVATE,
    /// Protected access
    PROTECTED,
    /// Public access
    PUBLIC,

    UNKNOWN(u8),
}

impl From<u8> for MethodAccess {
    fn from(value: u8) -> Self {
        match value {
            0 => MethodAccess::NONE,
            1 => MethodAccess::PRIVATE,
            2 => MethodAccess::PROTECTED,
            3 => MethodAccess::PUBLIC,
            _ => MethodAccess::UNKNOWN(value),
        }
    }
}

impl From<MethodAccess> for u8 {
    fn from(value: MethodAccess) -> u8 {
        match value {
            MethodAccess::NONE => 0,
            MethodAccess::PRIVATE => 1,
            MethodAccess::PROTECTED => 2,
            MethodAccess::PUBLIC => 3,
            MethodAccess::UNKNOWN(v) => v,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum MethodType {
    /// Regular instance method
    VANILLA,
    /// Virtual method
    VIRTUAL,
    /// Static method
    STATIC,
    /// Friend method
    FRIEND,
    /// Virtual method that introduces a new vtable slot
    INTRODUCING_VIRTUAL,
    /// Pure virtual method (abstract)
    PURE_VIRTUAL,
    /// Pure virtual method that introduces a new vtable slot
    PURE_INTRODUCING_VIRTUAL,

    UNKNOWN(u32),
}

impl From<u32> for MethodType {
    fn from(value: u32) -> Self {
        match value {
            0x00 => MethodType::VANILLA,
            0x01 => MethodType::VIRTUAL,
            0x02 => MethodType::STATIC,
            0x03 => MethodType::FRIEND,
            0x04 => MethodType::INTRODUCING_VIRTUAL,
            0x05 => MethodType::PURE_VIRTUAL,
            0x06 => MethodType::PURE_INTRODUCING_VIRTUAL,
            _ => MethodType::UNKNOWN(value),
        }
    }
}

impl From<MethodType> for u32 {
    fn from(value: MethodType) -> u32 {
        match value {
            MethodType::VANILLA => 0x00,
            MethodType::VIRTUAL => 0x01,
            MethodType::STATIC => 0x02,
            MethodType::FRIEND => 0x03,
            MethodType::INTRODUCING_VIRTUAL => 0x04,
            MethodType::PURE_VIRTUAL => 0x05,
            MethodType::PURE_INTRODUCING_VIRTUAL => 0x06,
            MethodType::UNKNOWN(v) => v,
        }
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


