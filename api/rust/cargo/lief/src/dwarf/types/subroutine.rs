use lief_ffi as ffi;

use crate::common::FromFFI;
use std::marker::PhantomData;
use crate::dwarf::types::DwarfType;
use crate::declare_fwd_iterator;
use crate::dwarf::Parameters;

/// This structure represents a `DW_TAG_subroutine_type`
pub struct Subroutine<'a> {
    ptr: cxx::UniquePtr<ffi::DWARF_types_Subroutine>,
    _owner: PhantomData<&'a ()>,
}

impl FromFFI<ffi::DWARF_types_Subroutine> for Subroutine<'_> {
    fn from_ffi(ptr: cxx::UniquePtr<ffi::DWARF_types_Subroutine>) -> Self {
        Self {
            ptr,
            _owner: PhantomData,
        }
    }
}

impl DwarfType for Subroutine<'_> {
    fn get_base(&self) -> &ffi::DWARF_Type {
        self.ptr.as_ref().unwrap().as_ref()
    }
}

impl Subroutine<'_> {
    /// [`Parameters`] of this subroutine
    pub fn parameters(&self) -> ParametersIt {
        ParametersIt::new(self.ptr.parameters())
    }
}

declare_fwd_iterator!(
    ParametersIt,
    Parameters<'a>,
    ffi::DWARF_Parameter,
    ffi::DWARF_types_Subroutine,
    ffi::DWARF_types_Subroutine_it_parameters
);
