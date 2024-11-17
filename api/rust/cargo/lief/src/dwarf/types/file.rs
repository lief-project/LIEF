use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

/// This structure represents a `DW_TAG_file_type`
pub struct File<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_File>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_File> for File<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_File>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for File<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
