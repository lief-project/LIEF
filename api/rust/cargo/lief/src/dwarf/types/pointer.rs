use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This structure represents a ``DW_TAG_pointer_type`` DWARF type.
pub struct Pointer<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Pointer>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Pointer> for Pointer<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Pointer>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Pointer<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Pointer<'_> {
    /// The type pointed by this pointer
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}
