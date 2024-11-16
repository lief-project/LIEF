use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This structure represents a `DW_TAG_set_type`
pub struct SetTy<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_SetTy>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_SetTy> for SetTy<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_SetTy>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for SetTy<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl SetTy<'_> {
    /// The underlying type referenced by this set-type.
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}


