use lief_ffi as ffi;

use super::commands::dylib::Dylib;
use super::commands::Segment;
use super::symbol::Symbol;
use std::{fmt, marker::PhantomData};

use crate::common::{into_optional, FromFFI};

#[derive(Debug)]
pub enum BindingInfo<'a> {
    Generic(Generic<'a>),
    Dyld(Dyld<'a>),
    Chained(Chained<'a>),
}

pub trait AsGeneric {
    #[doc(hidden)]
    fn as_generic(&self) -> &ffi::MachO_BindingInfo;

    fn library(&self) -> Option<Dylib> {
        into_optional(self.as_generic().library())
    }

    fn symbol(&self) -> Option<Symbol> {
        into_optional(self.as_generic().symbol())
    }

    fn segment(&self) -> Option<Segment> {
        into_optional(self.as_generic().segment())
    }

    fn address(&self) -> u64 {
        self.as_generic().address()
    }

    fn addend(&self) -> i64 {
        self.as_generic().addend()
    }

    fn library_ordinal(&self) -> i32 {
        self.as_generic().library_ordinal()
    }
}

impl std::fmt::Debug for &dyn AsGeneric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsGeneric")
            .field("address", &self.address())
            .field("addend", &self.addend())
            .field("library_ordinal", &self.library_ordinal())
            .finish()
    }
}

impl<'a> FromFFI<ffi::MachO_BindingInfo> for BindingInfo<'a> {
    fn from_ffi(ffi_entry: cxx::UniquePtr<ffi::MachO_BindingInfo>) -> Self {
        unsafe {
            let cmd_ref = ffi_entry.as_ref().unwrap();

            if ffi::MachO_ChainedBindingInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_BindingInfo>;
                    type To = cxx::UniquePtr<ffi::MachO_ChainedBindingInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                BindingInfo::Chained(Chained::from_ffi(raw))
            } else if ffi::MachO_DyldBindingInfo::classof(cmd_ref) {
                let raw = {
                    type From = cxx::UniquePtr<ffi::MachO_BindingInfo>;
                    type To = cxx::UniquePtr<ffi::MachO_DyldBindingInfo>;
                    std::mem::transmute::<From, To>(ffi_entry)
                };
                BindingInfo::Dyld(Dyld::from_ffi(raw))
            } else {
                BindingInfo::Generic(Generic::from_ffi(ffi_entry))
            }
        }
    }
}

pub struct Generic<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_BindingInfo>,
    _owner: PhantomData<&'a ()>,
}

impl fmt::Debug for Generic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn AsGeneric;
        f.debug_struct("Generic").field("base", &base).finish()
    }
}

impl<'a> FromFFI<ffi::MachO_BindingInfo> for Generic<'a> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_BindingInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsGeneric for Generic<'_> {
    fn as_generic(&self) -> &ffi::MachO_BindingInfo {
        self.ptr.as_ref().unwrap()
    }
}

pub struct Dyld<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_DyldBindingInfo>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum BINDING_CLASS {
    WEAK,
    LAZY,
    STANDARD,
    THREADED,
    UNKNOWN(u64),
}

impl BINDING_CLASS {
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00000001 => BINDING_CLASS::WEAK,
            0x00000002 => BINDING_CLASS::LAZY,
            0x00000003 => BINDING_CLASS::STANDARD,
            0x00000064 => BINDING_CLASS::THREADED,
            _ => BINDING_CLASS::UNKNOWN(value),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum BIND_TYPES {
    POINTER,
    TEXT_ABSOLUTE32,
    TEXT_PCREL32,
    UNKNOWN(u64),
}

impl BIND_TYPES {
    pub fn from_value(value: u64) -> Self {
        match value {
            0x00000001 => BIND_TYPES::POINTER,
            0x00000002 => BIND_TYPES::TEXT_ABSOLUTE32,
            0x00000003 => BIND_TYPES::TEXT_PCREL32,
            _ => BIND_TYPES::UNKNOWN(value),
        }
    }
}

impl Dyld<'_> {
    pub fn binding_class(&self) -> BINDING_CLASS {
        BINDING_CLASS::from_value(self.ptr.binding_class())
    }

    pub fn binding_type(&self) -> BIND_TYPES {
        BIND_TYPES::from_value(self.ptr.binding_type())
    }

    pub fn is_non_weak_definition(&self) -> bool {
        self.ptr.is_non_weak_definition()
    }

    pub fn original_offset(&self) -> u64 {
        self.ptr.original_offset()
    }
}

impl fmt::Debug for Dyld<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn AsGeneric;
        f.debug_struct("Dyld")
            .field("base", &base)
            .field("binding_class", &self.binding_class())
            .field("binding_type", &self.binding_type())
            .field("is_non_weak_definition", &self.is_non_weak_definition())
            .field("original_offset", &self.original_offset())
            .finish()
    }
}

impl FromFFI<ffi::MachO_DyldBindingInfo> for Dyld<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_DyldBindingInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsGeneric for Dyld<'_> {
    fn as_generic(&self) -> &ffi::MachO_BindingInfo {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

pub struct Chained<'a> {
    ptr: cxx::UniquePtr<ffi::MachO_ChainedBindingInfo>,
    _owner: PhantomData<&'a ()>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CHAINED_FORMAT {
    IMPORT,
    IMPORT_ADDEND,
    IMPORT_ADDEND64,
    UNKNOWN(u32),
}

impl CHAINED_FORMAT {
    pub fn from_value(value: u32) -> Self {
        match value {
            0x00000001 => CHAINED_FORMAT::IMPORT,
            0x00000002 => CHAINED_FORMAT::IMPORT_ADDEND,
            0x00000003 => CHAINED_FORMAT::IMPORT_ADDEND64,
            _ => CHAINED_FORMAT::UNKNOWN(value),
        }
    }
}

impl Chained<'_> {
    pub fn format(&self) -> CHAINED_FORMAT {
        CHAINED_FORMAT::from_value(self.ptr.format())
    }

    pub fn ptr_format(&self) -> u32 {
        self.ptr.ptr_format()
    }

    pub fn offset(&self) -> u32 {
        self.ptr.offset()
    }
}

impl fmt::Debug for Chained<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self as &dyn AsGeneric;
        f.debug_struct("Chained")
            .field("base", &base)
            .field("format", &self.format())
            .field("ptr_format", &self.ptr_format())
            .field("offset", &self.offset())
            .finish()
    }
}

impl FromFFI<ffi::MachO_ChainedBindingInfo> for Chained<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::MachO_ChainedBindingInfo>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl AsGeneric for Chained<'_> {
    fn as_generic(&self) -> &ffi::MachO_BindingInfo {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
