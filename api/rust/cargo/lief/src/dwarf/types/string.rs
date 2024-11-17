use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

/// This structure represents a `DW_TAG_string_type`
pub struct StringTy<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_StringTy>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_StringTy> for StringTy<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_StringTy>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for StringTy<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
