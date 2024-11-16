use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This structure represents a `DW_TAG_atomic_type`
pub struct Atomic<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Atomic>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Atomic> for Atomic<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_Atomic>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Atomic<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Atomic<'_> {
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}
