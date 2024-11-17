use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

/// This structure represents a `DW_TAG_interface_type`
pub struct Interface<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Interface>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Interface> for Interface<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_Interface>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Interface<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
