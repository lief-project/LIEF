use lief_ffi as ffi;

use crate::common::{into_optional, FromFFI};
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::dwarf::Type;

/// This structure represents a `DW_TAG_interface_type`
pub struct PointerToMember<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_PointerToMember>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_PointerToMember> for PointerToMember<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_PointerToMember>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for PointerToMember<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl PointerToMember<'_> {
    /// The type of the member referenced by this pointer
    pub fn underlying_type(&self) -> Option<Type> {
        into_optional(self.ptr.underlying_type())
    }

    /// The type that embeds this member
    pub fn containing_type(&self) -> Option<Type> {
        into_optional(self.ptr.containing_type())
    }
}


