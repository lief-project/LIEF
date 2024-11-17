use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

/// This structure represents a `DW_TAG_coarray_type`
pub struct Coarray<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Coarray>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Coarray> for Coarray<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_Coarray>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Coarray<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
