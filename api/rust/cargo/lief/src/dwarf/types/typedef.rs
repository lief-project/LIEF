use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This structure represents a `DW_TAG_typedef` DWARF type.
pub struct Typedef<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Typedef>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Typedef> for Typedef<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Typedef>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Typedef<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Typedef<'_> {
    /// The type aliased by this typedef
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}
