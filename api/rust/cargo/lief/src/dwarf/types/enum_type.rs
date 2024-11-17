use lief_ffi as ffi;

use crate::common:: FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

/// This structure represents a `DW_TAG_enumeration_type`
pub struct Enum<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Enum>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Enum> for Enum<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_Enum>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Enum<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
