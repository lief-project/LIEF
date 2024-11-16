use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This structure represents a `DW_TAG_rvalue_reference_type`
pub struct RValueReference<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_RValueReference>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_RValueReference> for RValueReference<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_RValueReference>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for RValueReference<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl RValueReference<'_> {
    /// The type of the member referenced by this pointer
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}


