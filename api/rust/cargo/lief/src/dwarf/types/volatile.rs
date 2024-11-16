use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This structure represents a `DW_TAG_volatile_type`
pub struct Volatile<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Volatile>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Volatile> for Volatile<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_Volatile>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Volatile<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Volatile<'_> {
    /// This underlying type
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}
