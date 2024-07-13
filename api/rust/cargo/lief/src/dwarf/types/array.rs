use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;

use crate::dwarf::Type;

/// This class represents a `DW_TAG_array_type`
pub struct Array<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Array>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Array> for Array<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Array>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Array<'_> {
    /// The underlying type of this array
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}

impl DwarfType for Array<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
