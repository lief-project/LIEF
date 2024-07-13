use lief_ffi as ffi;

use crate::common::{FromFFI, into_optional};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This class represents a `DW_TAG_const_type`
pub struct Const<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Const>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Const> for Const<'_> {
    fn from_ffi(cmd: cxx::UniquePtr<ffi::DWARF_types_Const>) -> Self {
        Self {
            ptr: cmd,
            _owner: PhantomData,
        }
    }
}

impl Const<'_> {
    /// The underlying type being const-ed by this type.
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }
}

impl DwarfType for Const<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}
