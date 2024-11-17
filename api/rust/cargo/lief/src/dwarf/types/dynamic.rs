use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

/// This structure represents a `DW_TAG_dynamic_type`
pub struct Dynamic<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Dynamic>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Dynamic> for Dynamic<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_Dynamic>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Dynamic<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
